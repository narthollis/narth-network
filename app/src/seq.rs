use opentelemetry_appender_tracing::layer::{OpenTelemetryTracingBridge, TracingSpanAttributes};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Initializes the global tracing registry with a stdout layer and an OTel/Seq layer.
/// Returns the SdkTracerProvider so the main function can trigger a `.shutdown()` on exit.
pub fn init_telemetry(seq_endpoint: &str) -> Result<OtelShutdown, Box<dyn std::error::Error>> {
    let resource = opentelemetry_sdk::resource::Resource::builder()
        .with_service_name("narth-net")
        .build();

    let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/traces", seq_endpoint))
        .with_protocol(Protocol::HttpBinary)
        .build()?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(trace_exporter)
        .with_resource(resource.clone())
        .build();

    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/logs", seq_endpoint))
        .with_protocol(Protocol::HttpBinary)
        .build()?;
    let log_provider = SdkLoggerProvider::builder()
        .with_batch_exporter(log_exporter)
        .with_resource(resource.clone())
        .build();

    let tracer = opentelemetry::trace::TracerProvider::tracer(&tracer_provider, "narth-net");
    let trace = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(EnvFilter::new("trace"));

    let logs = OpenTelemetryTracingBridge::builder(&log_provider)
        .with_tracing_span_attributes(TracingSpanAttributes::all())
        .build()
        .with_filter(EnvFilter::new("info,narth_net=trace,narth_net_app=trace"));

    // 4. Create your clean terminal logging layer
    let stdout_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_filter(EnvFilter::new("error,narth_net_app=info")); // Keeps terminal text clean; routes heavy trace info to Seq

    // 5. Register both layers globally
    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(trace)
        .with(logs)
        .init();

    Ok(OtelShutdown(Some(tracer_provider), Some(log_provider)))
}

pub struct OtelShutdown(Option<SdkTracerProvider>, Option<SdkLoggerProvider>);
impl OtelShutdown {
    pub fn shutdown(&self) {
        if let Some(t) = &self.0 {
            _ = t.shutdown();
        }
        if let Some(l) = &self.1 {
            _ = l.shutdown();
        }
    }
}
