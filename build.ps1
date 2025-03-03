cargo clean

Set-ExecutionPolicy Unrestricted -Scope CurrentUser

$RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none"

cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --release