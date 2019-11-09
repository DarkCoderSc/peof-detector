# peof-detector

This tiny project demonstrate how to use my tiny library `UntEOF.pas` to handle potential malicious data stored at the end of PE Files.

This technique is often used by Malware to store malicious files (wrapper), mal-plugins, configuration (botnets / rats / loader etc..) and so on.

Support both 32bit and 64bit PE File.

## Read / Write Plain Data

![EOF Read Write](https://www.phrozen.io/media/2019-11/peof-rw.png)

This project let you understand the concept of writing and reading data stored at the end of a PE File.

In this example, I store JSON String. But you could also store any kind of data (Records, Files etc..)

## Read EOF Data (Hex View)

![EOF Read As Hex](https://www.phrozen.io/media/2019-11/peof-hexview.png)

You can also read the full content of target file EOF as a plain text (displayed as text hex view).

## Scan for potential infected files (EOF Detection)

![EOF Detector](https://www.phrozen.io/media/2019-11/peof-detector.png)

I also wrote a tiny example (non recursive) about how to use that library to scan for infected files by EOF data (Based on PE Header informations).

## Then

- This detection function will be implemented in a futur project I'm working on.
- Port that library to Python.
