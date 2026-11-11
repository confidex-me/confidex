#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version")) {
        println!("confidexm {}", confidex_app::BUILD_VERSION);
        return Ok(());
    }
    let path = if let Some(path) = std::env::args_os().nth(1) {
        std::path::PathBuf::from(path)
    } else {
        confidex_native::database_path()?
    };
    let icon = image::load_from_memory(include_bytes!(
        "../assets/icons/Confidex.iconset/icon_256x256.png"
    ))?
    .into_rgba8();
    let icon = eframe::egui::IconData {
        width: icon.width(),
        height: icon.height(),
        rgba: icon.into_raw(),
    };
    eframe::run_native(
        "Confidex",
        eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
                .with_inner_size([1180., 780.])
                .with_min_inner_size([320., 400.])
                .with_icon(icon),
            ..Default::default()
        },
        Box::new(move |cc| {
            let runtime = confidex::native::NativeRuntime::new(path, cc.egui_ctx.clone())?;
            let mut app = confidex_ui::VaultApp::new(&cc.egui_ctx, Box::new(runtime))?;
            app.restore_sync_defaults(cc.storage);
            app.restore_device_unlock_settings(cc.storage);
            app.restore_auto_lock_settings(cc.storage);
            app.restore_generator_preferences(cc.storage);
            confidex::motion::install(&cc.egui_ctx);
            confidex::backup_files::install(&mut app);
            confidex::import_files::install(&mut app);
            confidex::image_files::install(&mut app);
            app.locale = confidex_ui::i18n::Localizer::from_preferences(sys_locale::get_locales())?;
            let mut clipboard = arboard::Clipboard::new().ok();
            app.set_clipboard_handler(move |text, done| {
                done(clipboard.as_mut().is_some_and(|c| c.set_text(text).is_ok()));
            });
            #[cfg(target_os = "macos")]
            confidex::native_quit::install(&cc.egui_ctx)?;
            Ok(Box::new(app))
        }),
    )?;
    Ok(())
}
#[cfg(target_arch = "wasm32")]
fn main() {}
