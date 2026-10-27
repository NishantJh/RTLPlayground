# Agent guide: RTLPlayground (fork)

Firmware for RTL8372/RTL8373 switches. This is a fork of logicog/RTLPlayground. Keep changes upstreamable. Project plans live in `NishantJh/Horaco-Switch-Firmware` (`docs/CONTEXT.md`).

## Where things live

- Top-level `*.c`/`*.h`: firmware core. `rtlplayground.c` (serial CLI), `cmd_parser.c`, `cmd_editor.c`, `boot.c`, `machine_init.c`, `dhcp.c`, `dns.c`, `ntp.c`, `syslog.c`, `sfp.c`.
- `rtl837x_*.c`/`.h`: RTL837x drivers. Examples: `rtl837x_lacp`, `rtl837x_stp`, `rtl837x_igmp`, `rtl837x_storm`, `rtl837x_lldp`, `rtl837x_port`, `rtl837x_phy`, `rtl837x_flash`, `rtl837x_regs.h`.
- `httpd/`: web server. `html/`: web UI source (`index.html`, `app.js`), minified into flash at build time.
- `machine/`: one `<MACHINE>.c` and `<MACHINE>.h` pair per board. `machine.h` selects one.
- `uip/`: TCP/IP stack (third-party style code, change only for networking work).
- `tools/`: host build tools (`fileadder`, `imagebuilder`, `crc_calculator`, `httpd_sim`).
- `installer/`: OEM web-upgrade image builder.
- `test/`: tests. `doc/`: feature docs (`stp.md`, `lacp.md`, `vlan.md`, `storm_control.md`, and others).

## Do not read

- `output/`, `html_data.c`, `html_data.h`, `version.h`: generated build output. Do not edit them.
- `*.bin`, `*.img`, `doc/images/`: binaries and images.
- `uip/` and `tools/` unless the task touches them.
- Do not read the whole tree. Search for a symbol with grep, then open the file it lives in.

## Build and test

- Dependencies: `make gcc sdcc xxd python3 libjson-c-dev zlib1g-dev`, with sdcc 4.5. Or use Docker: `docker build -t rtlplayground-dev .`
- Build for the HC-SWTGW218AS: `make MACHINE=SWTG018AS_A_V_2_0`.
- Compile every machine: `make machine_check MACHINE=<any>`.
- Run `CI=1 make ...` before pushing. It turns warnings into errors.
- Unit and host tests: `make -C test`.
- Host tools only: `make -C tools`.
- A build that changes flash layout or config location must be checked against `Makefile` offsets and `machine.h`.

## Rules

- All changes go through a PR. No direct pushes to `main`, which is protected.
- Merge this PR before its matching test PR in `Horaco-Switch-Firmware`.
- Never commit stock vendor firmware or built `.bin` files.
- Never flash a switch from an agent. Nishant flashes only after tests pass and a full SPI backup exists.
- Keep board-specific code under `machine/`. Shared code must stay upstreamable.
