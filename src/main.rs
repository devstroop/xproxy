use xproxy_core::{Config, Proxy};
use xproxy_forward::ForwardProxy;
use xproxy_reverse::ReverseProxy;

fn main() -> xproxy_core::Result<()> {
    let config = Config::default();

    let fwd = ForwardProxy::new(config.clone());
    let rev = ReverseProxy::new(config);

    println!("xproxy — proxies registered: {}, {}", fwd.name(), rev.name());
    println!("mode check: {:?} / {:?}", fwd.mode(), rev.mode());
    Ok(())
}
