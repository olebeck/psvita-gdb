target := "armv7-sony-vita-newlibeabihf"
project := "vita-gdb"
vitaip := "192.168.178.21"

build:
    cd {{project}} && cargo build --verbose
    vita-elf-create -e vita-gdb/exports.yml -s target/{{target}}/debug/{{project}}.elf target/{{target}}/debug/{{project}}.velf
    vita-make-fself -c target/{{target}}/debug/{{project}}.velf target/{{target}}/debug/{{project}}.skprx

release:
    cd {{project}} && cargo build --release
    vita-elf-create -e vita-gdb/exports.yml -s target/{{target}}/release/{{project}}.elf target/{{target}}/release/{{project}}.velf
    vita-make-fself -c target/{{target}}/release/{{project}}.velf target/{{target}}/release/{{project}}.skprx

clean:
    cargo clean

test:
    cd arm-next-pc && cargo +nightly test --features std -Zbuild-std --profile test --target x86_64-unknown-linux-gnu

push: release
    curl -T target/{{target}}/release/{{project}}.skprx ftp://{{vitaip}}:1337/ur0:tai/{{project}}.skprx

reboot:
    echo reboot | ncat {{vitaip}} 1338
