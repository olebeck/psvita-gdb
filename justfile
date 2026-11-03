target := "armv7-sony-vita-newlibeabihf"
project := "vita-gdb"
vitaip := "192.168.178.21"

self profile:
    vita-elf-create -e {{project}}/exports.yml -s target/{{target}}/{{profile}}/{{project}}.elf target/{{target}}/{{profile}}/{{project}}.velf
    vita-make-fself -c target/{{target}}/{{profile}}/{{project}}.velf target/{{target}}/{{profile}}/{{project}}.skprx

build:
    cd {{project}} && cargo +nightly build -Zbuild-std=core --verbose
    @just self debug

release:
    cd {{project}} && cargo +nightly build -Zbuild-std=core --release
    @just self release

clean:
    cargo clean

test:
    cd arm-next-pc && cargo +nightly test --features std --target x86_64-unknown-linux-gnu

push: release
    curl -T target/{{target}}/release/{{project}}.skprx ftp://{{vitaip}}:1337/ur0:tai/{{project}}.skprx

reboot:
    echo reboot | ncat {{vitaip}} 1338
