//! Small shared drawing helpers for the vault screens.
use eframe::egui::{self, Color32, Pos2, Rect, Stroke, Vec2};

#[derive(Clone, Copy)]
pub enum Icon {
    Close,
    Vault,
    Settings,
    Copy,
    Lock,
    Items,
    Plus,
    Back,
    Trash,
    Eye,
    EyeOff,
    LargeType,
    Alert,
    Sun,
    Globe,
    Check,
    Refresh,
    Spinner,
    Generate,
    Calendar,
    Key,
    Note,
    Grip,
    Search,
    Card,
    Identity,
}
impl Icon {
    pub fn paint(self, ui: &egui::Ui, rect: Rect, color: Color32) {
        let r = Rect::from_center_size(rect.center(), Vec2::splat(20.));
        let point = |x: f32, y: f32| Pos2::new(r.left() + x, r.top() + y);
        let stroke = Stroke::new(1.6, color);
        let line = |points: &[(f32, f32)]| {
            ui.painter().add(egui::Shape::line(
                points.iter().map(|&(x, y)| point(x, y)).collect(),
                stroke,
            ));
        };
        let circle = |x, y, radius| {
            ui.painter().circle_stroke(point(x, y), radius, stroke);
        };
        match self {
            Self::Card => {
                ui.painter().rect_stroke(
                    Rect::from_min_max(point(2., 4.), point(18., 16.)),
                    2.,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                line(&[(2., 8.), (18., 8.)]);
                line(&[(5., 12.), (9., 12.)]);
            }
            Self::Identity => {
                ui.painter().rect_stroke(
                    Rect::from_min_max(point(2., 4.), point(18., 16.)),
                    2.,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                circle(6.5, 8.5, 1.7);
                line(&[(4., 14.), (4.5, 11.5), (8.5, 11.5), (9., 14.)]);
                line(&[(11., 8.), (16., 8.)]);
                line(&[(11., 12.), (16., 12.)]);
            }
            Self::Spinner => egui::Spinner::new().color(color).paint_at(ui, r),
            Self::Close => {
                line(&[(5., 5.), (15., 15.)]);
                line(&[(15., 5.), (5., 15.)]);
            }
            Self::Calendar => {
                ui.painter().rect_stroke(
                    Rect::from_min_max(point(3., 4.), point(17., 18.)),
                    2.,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                line(&[(3., 8.), (17., 8.)]);
                line(&[(7., 2.), (7., 6.)]);
                line(&[(13., 2.), (13., 6.)]);
                for (x, y) in [(7., 11.), (13., 11.), (7., 15.), (13., 15.)] {
                    ui.painter().circle_filled(point(x, y), 0.8, color);
                }
            }
            Self::Generate => {
                ui.painter().rect_stroke(
                    Rect::from_min_max(point(3., 3.), point(17., 17.)),
                    3.,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                for (x, y) in [
                    (6.5, 6.5),
                    (13.5, 6.5),
                    (10., 10.),
                    (6.5, 13.5),
                    (13.5, 13.5),
                ] {
                    ui.painter().circle_filled(point(x, y), 1.1, color);
                }
            }
            Self::Search => {
                circle(8., 8., 6.);
                line(&[(12.5, 12.5), (18., 18.)]);
            }
            Self::Grip => {
                for x in [7., 13.] {
                    for y in [5., 10., 15.] {
                        ui.painter().circle_filled(point(x, y), 1.2, color);
                    }
                }
            }
            Self::Settings => {
                let teeth = (0..32)
                    .map(|i| {
                        let angle = std::f32::consts::TAU * i as f32 / 32.;
                        let radius = if matches!(i % 4, 1 | 2) { 8.5 } else { 6.5 };
                        point(10. + radius * angle.cos(), 10. + radius * angle.sin())
                    })
                    .collect();
                ui.painter().add(egui::Shape::closed_line(teeth, stroke));
                circle(10., 10., 3.);
            }
            Self::Copy => {
                ui.painter().rect_stroke(
                    Rect::from_min_max(point(7., 7.), point(18., 18.)),
                    2.,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                line(&[(13., 3.), (3., 3.), (3., 13.)]);
            }
            Self::Vault | Self::Key => {
                circle(7., 7., 3.5);
                line(&[(9.5, 9.5), (16., 16.), (18., 14.), (16., 12.)]);
            }
            Self::Lock => {
                ui.painter().rect_stroke(
                    Rect::from_min_max(point(4., 8.), point(16., 18.)),
                    2.,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                line(&[
                    (6., 8.),
                    (6., 5.),
                    (8., 2.),
                    (12., 2.),
                    (14., 5.),
                    (14., 8.),
                ]);
            }
            Self::Items => {
                line(&[(2., 7.), (10., 2.), (18., 7.), (10., 12.), (2., 7.)]);
                line(&[(2., 11.), (10., 16.), (18., 11.)]);
            }
            Self::Plus => {
                line(&[(3., 10.), (17., 10.)]);
                line(&[(10., 3.), (10., 17.)]);
            }
            Self::Back => {
                line(&[(12., 3.), (5., 10.), (12., 17.)]);
            }
            Self::Trash => {
                line(&[(3., 5.), (17., 5.)]);
                line(&[(5., 5.), (6., 18.), (14., 18.), (15., 5.)]);
                line(&[(7., 5.), (7., 2.), (13., 2.), (13., 5.)]);
            }
            Self::Eye | Self::EyeOff => {
                line(&[
                    (1., 10.),
                    (5., 5.),
                    (10., 3.),
                    (15., 5.),
                    (19., 10.),
                    (15., 15.),
                    (10., 17.),
                    (5., 15.),
                    (1., 10.),
                ]);
                circle(10., 10., 3.);
                if matches!(self, Self::EyeOff) {
                    line(&[(2., 2.), (18., 18.)]);
                }
            }
            Self::LargeType => {
                line(&[(2., 3.), (18., 3.)]);
                line(&[(10., 3.), (10., 18.)]);
                line(&[(6., 18.), (14., 18.)]);
                line(&[(2., 3.), (2., 6.)]);
                line(&[(18., 3.), (18., 6.)]);
            }
            Self::Alert => {
                line(&[(10., 2.), (19., 18.), (1., 18.), (10., 2.)]);
                line(&[(10., 7.), (10., 12.)]);
                circle(10., 15., 0.5);
            }
            Self::Sun => {
                circle(10., 10., 4.);
                for (a, b) in [
                    ((10., 0.), (10., 3.)),
                    ((10., 17.), (10., 20.)),
                    ((0., 10.), (3., 10.)),
                    ((17., 10.), (20., 10.)),
                    ((3., 3.), (5., 5.)),
                    ((15., 15.), (17., 17.)),
                    ((3., 17.), (5., 15.)),
                    ((15., 5.), (17., 3.)),
                ] {
                    line(&[a, b]);
                }
            }
            Self::Globe => {
                circle(10., 10., 8.);
                line(&[(2., 10.), (18., 10.)]);
                line(&[
                    (10., 2.),
                    (6., 6.),
                    (6., 14.),
                    (10., 18.),
                    (14., 14.),
                    (14., 6.),
                    (10., 2.),
                ]);
            }
            Self::Check => {
                line(&[(3., 10.), (8., 15.), (17., 5.)]);
            }
            Self::Refresh => {
                line(&[
                    (17., 8.),
                    (15., 4.),
                    (10., 2.),
                    (5., 4.),
                    (2., 8.),
                    (3., 14.),
                    (8., 18.),
                    (14., 17.),
                    (17., 13.),
                ]);
                line(&[(17., 2.), (17., 8.), (11., 8.)]);
            }
            Self::Note => {
                line(&[
                    (4., 1.),
                    (12., 1.),
                    (17., 6.),
                    (17., 19.),
                    (4., 19.),
                    (4., 1.),
                ]);
                line(&[(12., 1.), (12., 6.), (17., 6.)]);
                line(&[(7., 10.), (14., 10.)]);
                line(&[(7., 14.), (13., 14.)]);
            }
        }
    }
}
