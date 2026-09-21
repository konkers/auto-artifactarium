//! Typed proto subset (codegen) plus the full-schema dynamic `FileDescriptor`
//! used by the reflection-based JSON serialization.
//!
//! The full V70 schema ships as an embedded `FileDescriptorSet` data blob
//! instead of ~27MB of generated Rust; only the handful of messages whose
//! fields are accessed as concrete Rust types get codegen.

pub mod protos {
    mod generated {
        include!(concat!(env!("OUT_DIR"), "/typed_out/mod.rs"));
    }
    // Re-export the typed subset under `crate::gen::protos::*` so existing
    // call sites keep working. The codegen's own static `file_descriptor` is
    // shadowed by the dynamic one below.
    pub use generated::protos::*;

    /// Full V70 schema (~3500 messages), built once at runtime from the
    /// embedded descriptor set.
    pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
        use ::protobuf::Message as _;
        static FD: ::std::sync::OnceLock<::protobuf::reflect::FileDescriptor> =
            ::std::sync::OnceLock::new();
        FD.get_or_init(|| {
            let bytes: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/full_fdset.bin"));
            let set = ::protobuf::descriptor::FileDescriptorSet::parse_from_bytes(bytes)
                .expect("embedded FileDescriptorSet parses");
            let mut fds = ::protobuf::reflect::FileDescriptor::new_dynamic_fds(set.file, &[])
                .expect("embedded FileDescriptorSet builds");
            fds.remove(0)
        })
    }
}
