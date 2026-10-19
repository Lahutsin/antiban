use super::*;
use tao::{
    event::{Event as TaoEvent, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::macos::{ActivationPolicy, EventLoopExtMacOS},
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIconBuilder,
};

pub(super) fn run(options: Options) -> Result<()> {
    let artwork = icon_pixels()?;
    let mut event_loop = EventLoopBuilder::<Event>::with_user_event().build();
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |_| {
        if let Err(error) = proxy.send_event(Event::Quit) {
            eprintln!("Cannot request quit: {error:?}");
        }
    }));
    let proxy = event_loop.create_proxy();
    ctrlc::set_handler(move || {
        if let Err(error) = proxy.send_event(Event::Quit) {
            eprintln!("Cannot request quit: {error:?}");
        }
    })?;
    let mut view = View::default();
    let menu = Menu::new();
    let status = MenuItem::new(&view.label, false, None);
    let details = view
        .details
        .each_ref()
        .map(|label| MenuItem::new(label, false, None));
    let quit = MenuItem::new("Quit (remove protection)", true, None);
    menu.append_items(&[
        &status,
        &details[0],
        &details[1],
        &details[2],
        &PredefinedMenuItem::separator(),
        &quit,
    ])?;
    let mut icon = None;
    let mut worker = None;
    let mut options = Some(options);
    let proxy = event_loop.create_proxy();
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        let result = (|| -> Result<bool> {
            match event {
                TaoEvent::NewEvents(StartCause::Init) => {
                    icon = Some(
                        TrayIconBuilder::new()
                            .with_menu(Box::new(menu.clone()))
                            .with_tooltip("Antiban")
                            .with_icon(Icon::from_rgba(
                                pixels(&artwork, view.color),
                                ICON_SIZE,
                                ICON_SIZE,
                            )?)
                            .build()?,
                    );
                    let worker_proxy = proxy.clone();
                    worker = Some(Worker::start(
                        options.take().context("Tray already started")?,
                        move |event| {
                            if let Err(error) = worker_proxy.send_event(event) {
                                eprintln!("Tray closed before receiving monitor event: {error:?}");
                            }
                        },
                    )?);
                    proxy.send_event(Event::Refresh).map_err(|error| {
                        anyhow::anyhow!("Cannot wake tray event loop: {error:?}")
                    })?;
                }
                TaoEvent::UserEvent(event) => {
                    if let Some(worker) = &worker {
                        if view.event(event, worker)? {
                            return Ok(true);
                        }
                    }
                    status.set_text(&view.label);
                    for (item, text) in details.iter().zip(&view.details) {
                        item.set_text(text);
                    }
                    quit.set_enabled(!view.quitting);
                    if let Some(icon) = &icon {
                        icon.set_icon(Some(Icon::from_rgba(
                            pixels(&artwork, view.color),
                            ICON_SIZE,
                            ICON_SIZE,
                        )?))?;
                        icon.set_tooltip(Some(&view.label))?;
                    }
                }
                _ => {}
            }
            Ok(false)
        })();
        match result {
            Ok(true) => {
                icon.take();
                *flow = ControlFlow::Exit;
            }
            Err(error) => {
                eprintln!("Tray error: {error:#}");
                status.set_text(format!("Error: {error:#}"));
                if worker.is_none() {
                    icon.take();
                    *flow = ControlFlow::Exit;
                }
            }
            Ok(false) => {}
        }
    })
}
