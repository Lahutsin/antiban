use super::*;
use ksni::{blocking::TrayMethods, menu::StandardItem, Icon, MenuItem, Tray};

struct Indicator {
    label: String,
    details: [String; 3],
    color: Color,
    artwork: Vec<u8>,
    quitting: bool,
    events: Sender<Event>,
}

impl Tray for Indicator {
    fn id(&self) -> String {
        "antiban".into()
    }

    fn title(&self) -> String {
        format!("Antiban: {}", self.label)
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        let mut argb = pixels(&self.artwork, self.color);
        for pixel in argb.as_chunks_mut::<4>().0 {
            pixel.rotate_right(1);
        }
        vec![Icon {
            width: ICON_SIZE as i32,
            height: ICON_SIZE as i32,
            data: argb,
        }]
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items = vec![StandardItem {
            label: self.label.clone(),
            enabled: false,
            ..Default::default()
        }
        .into()];
        items.extend(self.details.iter().map(|label| {
            StandardItem {
                label: label.clone(),
                enabled: false,
                ..Default::default()
            }
            .into()
        }));
        items.extend([
            MenuItem::Separator,
            StandardItem {
                label: if self.quitting {
                    "Quitting..."
                } else {
                    "Quit (remove protection)"
                }
                .into(),
                enabled: !self.quitting,
                activate: Box::new(|this: &mut Self| {
                    if let Err(error) = this.events.send(Event::Quit) {
                        eprintln!("Cannot request quit: {error}");
                    }
                }),
                ..Default::default()
            }
            .into(),
        ]);
        items
    }
}

pub(super) fn run(options: Options) -> Result<()> {
    let (events, incoming) = mpsc::channel();
    let mut view = View::default();
    let artwork = icon_pixels()?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let handle = loop {
        let result = Indicator {
            label: view.label.clone(),
            details: view.details.clone(),
            color: view.color,
            artwork: artwork.clone(),
            quitting: false,
            events: events.clone(),
        }
        .spawn();
        match result {
            Ok(handle) => break handle,
            Err(error) if options.installed_helper && Instant::now() < deadline => {
                eprintln!("Waiting for login tray host: {error}; retrying in 2 seconds");
                thread::sleep(Duration::from_secs(2));
            }
            Err(error) => {
                return Err(error).context(
                    "Cannot create tray icon; a StatusNotifier/AppIndicator host is required",
                )
            }
        }
    };
    ctrlc::set_handler({
        let events = events.clone();
        move || {
            if let Err(error) = events.send(Event::Quit) {
                eprintln!("Cannot request quit: {error}");
            }
        }
    })?;
    let worker = Worker::start(options, move |event| {
        if let Err(error) = events.send(event) {
            eprintln!("Tray closed before receiving monitor event: {error}");
        }
    })?;
    for event in incoming {
        if view.event(event, &worker)? {
            break;
        }
        handle
            .update(|tray| {
                tray.label = view.label.clone();
                tray.details = view.details.clone();
                tray.color = view.color;
                tray.quitting = view.quitting;
            })
            .context("Tray service disconnected; protection may remain blocked")?;
    }
    Ok(())
}
