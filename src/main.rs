use eframe::{
    egui,
    egui::{Color32, RichText, Stroke, Vec2},
};
use regex::Regex;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 420.0])
            .with_resizable(false)
            .with_title("Ben's Phishing Detector"),
        ..Default::default()
    };

    eframe::run_native(
        "Ben's Phishing Detector",
        options,
        Box::new(|cc| {
            configure_theme(&cc.egui_ctx);
            Box::new(BensPhishingDetector::default())
        }),
    )
}

fn configure_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    style.visuals.window_fill = Color32::from_rgb(32, 32, 32);
    style.visuals.panel_fill = Color32::from_rgb(36, 36, 36);
    style.visuals.faint_bg_color = Color32::from_rgb(46, 46, 46);
    style.visuals.extreme_bg_color = Color32::from_rgb(24, 24, 24);

    style.visuals.override_text_color = Some(Color32::from_rgb(215, 215, 215));

    style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(40, 40, 40);
    style.visuals.widgets.noninteractive.bg_stroke =
        Stroke::new(1.0, Color32::from_rgb(75, 75, 75));

    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(58, 58, 58);
    style.visuals.widgets.inactive.bg_stroke =
        Stroke::new(1.0, Color32::from_rgb(90, 90, 90));

    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(72, 72, 72);
    style.visuals.widgets.hovered.bg_stroke =
        Stroke::new(1.0, Color32::from_rgb(130, 130, 130));

    style.visuals.widgets.active.bg_fill = Color32::from_rgb(90, 90, 90);
    style.visuals.widgets.active.bg_stroke =
        Stroke::new(1.0, Color32::from_rgb(160, 160, 160));

    style.spacing.item_spacing = Vec2::new(10.0, 12.0);
    style.spacing.button_padding = Vec2::new(14.0, 10.0);
    style.spacing.window_margin = egui::Margin::same(16.0);
    style.visuals.window_rounding = 8.0.into();
    style.visuals.widgets.inactive.rounding = 6.0.into();
    style.visuals.widgets.hovered.rounding = 6.0.into();
    style.visuals.widgets.active.rounding = 6.0.into();

    ctx.set_style(style);
}

#[derive(Default)]
struct BensPhishingDetector {
    url_input: String,
    risk_rating: i32,
    indicators: Vec<String>,
    result_message: String,
    scanned: bool,
}

impl eframe::App for BensPhishingDetector {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);

            ui.heading(
                RichText::new("Ben's Phishing Detector")
                    .size(28.0)
                    .color(Color32::from_rgb(225, 225, 225)),
            );

            ui.label(
                RichText::new("Analyze suspicious URLs for phishing indicators")
                    .color(Color32::from_rgb(170, 170, 170)),
            );

            ui.separator();
            ui.add_space(6.0);

            ui.label(
                RichText::new("Enter URL to analyze:")
                    .size(18.0)
                    .color(Color32::from_rgb(215, 215, 215)),
            );

            ui.add(
                egui::TextEdit::singleline(&mut self.url_input)
                    .hint_text("https://example.com")
                    .desired_width(520.0),
            );

            if ui
                .add_sized(
                    [160.0, 36.0],
                    egui::Button::new(
                        RichText::new("Analyze URL")
                            .size(16.0)
                            .color(Color32::from_rgb(235, 235, 235)),
                    ),
                )
                .clicked()
            {
                let (risk_rating, indicators) = check_url(&self.url_input);
                self.risk_rating = risk_rating;
                self.indicators = indicators;
                self.result_message = classify_result(self.risk_rating).to_string();
                self.scanned = true;
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            if self.scanned {
                ui.label(
                    RichText::new("Analysis Result")
                        .size(20.0)
                        .color(Color32::from_rgb(220, 220, 220)),
                );

                let risk_color = if self.risk_rating >= 3 {
                    Color32::from_rgb(190, 70, 70)
                } else if self.risk_rating == 2 {
                    Color32::from_rgb(180, 150, 90)
                } else {
                    Color32::from_rgb(160, 160, 160)
                };

                ui.label(
                    RichText::new(format!("Risk Rating: {}", self.risk_rating))
                        .size(18.0)
                        .color(Color32::from_rgb(220, 220, 220)),
                );

                ui.label(
                    RichText::new(format!("Result: {}", self.result_message))
                        .size(22.0)
                        .strong()
                        .color(risk_color),
                );

                ui.add_space(8.0);

                if self.indicators.is_empty() {
                    ui.label(
                        RichText::new("Indicators: None detected")
                            .color(Color32::from_rgb(190, 190, 190)),
                    );
                } else {
                    ui.label(
                        RichText::new("Indicators:")
                            .size(18.0)
                            .color(Color32::from_rgb(215, 215, 215)),
                    );

                    for indicator in &self.indicators {
                        ui.label(
                            RichText::new(format!("• {}", indicator))
                                .color(Color32::from_rgb(200, 200, 200)),
                        );
                    }
                }

                ui.add_space(10.0);

                ui.label(
                    RichText::new(user_guidance(self.risk_rating))
                        .color(Color32::from_rgb(185, 185, 185)),
                );
            } else {
                ui.label(
                    RichText::new("Ben's Phishing Detector is ready.")
                        .color(Color32::from_rgb(160, 160, 160)),
                );
            }
        });
    }
}

fn check_url(url: &str) -> (i32, Vec<String>) {
    let parsed_domain = extract_domain(url);

    let mut risk_rating = 0;
    let mut indicators: Vec<String> = Vec::new();

    if re_has_suspicious_domain_chars(&parsed_domain) {
        risk_rating += 1;
        indicators.push("Suspicious characters in domain".to_string());
    }

    if !url.starts_with("http://") && !url.starts_with("https://") {
        risk_rating += 1;
        indicators.push("Missing http/https".to_string());
    }

    if url.starts_with("http://") {
        risk_rating += 1;
        indicators.push("Missing HTTPS".to_string());
    }

    if is_ip_address(&parsed_domain) {
        risk_rating += 2;
        indicators.push("IP address used instead of domain".to_string());
    }

    let sus_words = ["login failed", "verify", "alert", "secure", "account"];
    let cssus_words = ["Free", "Urgent", "Prize", "Last Chance", "Expire"];

    let lower_url = url.to_lowercase();

    for word in sus_words {
        if lower_url.contains(&word.to_lowercase()) {
            risk_rating += 1;
            indicators.push(format!("Suspicious keyword detected: {}", word));
        }
    }

    for word in cssus_words {
        if url.contains(word) {
            risk_rating += 2;
            indicators.push(format!("Case-sensitive keyword detected: {}", word));
        }
    }

    (risk_rating, indicators)
}

fn extract_domain(url: &str) -> String {
    let cleaned = url
        .trim()
        .replace("https://", "")
        .replace("http://", "");

    cleaned
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

fn re_has_suspicious_domain_chars(domain: &str) -> bool {
    let regex = Regex::new(r"[^\w\.-]").unwrap();
    regex.is_match(domain)
}

fn is_ip_address(domain: &str) -> bool {
    let regex = Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$").unwrap();
    regex.is_match(domain)
}

fn classify_result(risk_rating: i32) -> &'static str {
    if risk_rating >= 3 {
        "HIGH RISK"
    } else if risk_rating == 2 {
        "MEDIUM RISK"
    } else {
        "LOW RISK"
    }
}

fn user_guidance(risk_rating: i32) -> &'static str {
    if risk_rating >= 3 {
        "This URL is very likely to be a phishing attempt. Do not click it without precaution."
    } else if risk_rating == 2 {
        "This URL has some suspicious indicators. Be cautious when interacting with it."
    } else {
        "This URL appears to be safer. Thank you for using Ben's Phishing Detector."
    }
}