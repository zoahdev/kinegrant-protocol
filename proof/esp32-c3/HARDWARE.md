# Hardware and power gate

Status: purchasing and physical assembly are **not yet complete**. This document
is a pre-purchase safety gate for the paper-barrier proof, not a wiring claim for
an unidentified ESP32-C3 SuperMini clone.

## Purchase ceiling

The complete new-purchase cart must remain between CNY 100 and 170, with a hard
ceiling of CNY 200 including shipping. Reuse an existing USB data cable or safe
5 V supply only if its condition and rating are known.

| Item | Requirement | Maximum allocation |
| --- | --- | ---: |
| ESP32-C3 SuperMini | one board, USB connector and pin labels visible | CNY 30 |
| SG90-class micro servo | one genuine or traceable 4.8–6 V unit | CNY 20 |
| SSD1306 OLED | one I2C module that can run at 3.3 V | CNY 25 |
| Breadboard, jumpers, button | no loose or damaged contacts | CNY 30 |
| Decoupling | 470–1000 uF electrolytic plus 100 nF ceramic | CNY 10 |
| Servo power path | regulated 5 V supply/breakout and cable, at least 1 A | CNY 35 |
| Paper fixture | lightweight paper/card only; no rigid latch | CNY 10 |
| Contingency | shipping or one replacement lead | CNY 10 |

Maximum planned allocation: **CNY 170**. Do not substitute a larger motor,
battery pack, relay, solenoid, or mains-powered supply to use the remaining
budget.

SG90-labelled products vary substantially by manufacturer and clone. Before
purchase, confirm the exact listing's voltage, connector order, dimensions, and
seller traceability. Do not rely on an online current figure as a safety limit.

## Power architecture

```text
computer USB data/power ---------------- ESP32-C3 board
                                            |
                                            +-- 3.3 V --> OLED only
                                            |
GPIO4 (3.3 V PWM, provisional) -------------+--------> servo signal

regulated 5 V servo supply ---------------------------> servo V+
servo supply GND ---------------------------+----------> servo GND
ESP32-C3 GND -------------------------------+

470–1000 uF capacitor: across servo 5 V and GND near the connector
100 nF capacitor:      across servo 5 V and GND near the connector
```

Rules:

1. Never power the servo from the ESP32-C3 3.3 V pin.
2. Do not assume the board's USB/5 V trace can tolerate servo startup or stall
   current. Use the separate regulated servo rail and join grounds only.
3. Do not connect the external servo 5 V rail to the board's 5 V pin while the
   board is USB-powered. This prevents accidental back-powering between sources.
4. Never place 5 V on an ESP32-C3 GPIO. Espressif specifies a 3.6 V absolute
   maximum for the chip's input power domain; board-level protection on an
   unidentified clone must not be assumed.
5. Power the OLED at 3.3 V so any on-board I2C pull-ups also remain at 3.3 V.
6. Observe electrolytic-capacitor polarity. Disconnect power before rewiring.
7. Use only an intact, regulated, extra-low-voltage supply. No exposed mains
   wiring or improvised lithium-cell charging is allowed.

Reference: the official
[ESP32-C3 datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-c3_datasheet_en.pdf)
and [DevKitM-1 power documentation](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32c3/esp32-c3-devkitm-1/user_guide.html).
The selected SuperMini is not the DevKitM-1; its actual schematic and pinout must
be checked separately.

## Provisional signals

These assignments intentionally avoid the documented GPIO2, GPIO8, and GPIO9
strapping pins, GPIO18/19 USB data pins, and GPIO20/21 UART pins. They are valid
only if the purchased board exposes and labels the same GPIO numbers.

| Function | Provisional pin | Electrical behavior |
| --- | --- | --- |
| Servo control | GPIO4 | 3.3 V output; local firmware maps logical positions to bounded PWM |
| OLED SDA | GPIO5 | 3.3 V I2C with board/module pull-up checked |
| OLED SCL | GPIO6 | 3.3 V I2C with board/module pull-up checked |
| Test button | GPIO7 to GND | internal pull-up; pressed is low |

Before first power-on, compare the seller's pinout, the board silkscreen, and a
continuity check. If any disagree, stop and revise this table. The ESP-IDF LEDC
driver can generate the servo waveform, but only the two locally calibrated
logical endpoints may be reachable from a signed command.

## Mechanical limits

- Attach only a light paper or thin-card flap with tape or a loose linkage.
- Start with a small travel range and increase only until movement is visible.
- Keep fingers, hair, cables, and rigid objects outside the travel path.
- Do not drive against a mechanical stop. Buzzing or repeated correction means
  disconnect power and reduce the configured travel.
- The safe state is servo detached or the paper flap resting without stored
  mechanical energy.

## First-power checklist

- [ ] Exact board photo, listing, pinout, and USB connector recorded.
- [ ] Cart total is at most CNY 200 and contains no prohibited device.
- [ ] Servo rail measures approximately 5 V before the servo is connected.
- [ ] OLED rail measures approximately 3.3 V.
- [ ] ESP32-C3 and servo grounds are common; their positive rails are not tied.
- [ ] Capacitor polarity and servo connector order have been checked twice.
- [ ] Firmware boots locked with the servo signal inactive.
- [ ] GPIO self-test and OLED status work before the servo receives power.
- [ ] First servo test uses the paper flap, a small travel range, and a person at
  the power disconnect.

Stop immediately on reset loops, hot components, odor, damaged insulation,
servo chatter, or unexpected movement. Record the failure; do not bypass the
gate to make a demonstration look successful.
