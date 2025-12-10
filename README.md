\# 🛡️ FOS Antivirus (Free Open Source)



FOS Antivirus is a modern, lightweight, and high-performance security scanner for Windows. Built using \*\*C\*\*, it provides a clean user interface to scan, detect, and quarantine malicious fies.





\## ✨ Features



\- \*\*Dashboard Overview:\*\* quick access to common tasks.

\- \*\*Signature Scanning:\*\* Matches file hashes against a database of known threats.

\- \*\*Custom Scan:\*\* Browse and select specific directories to scan.

\- \*\*Quarantine System:\*\* Safely moves threats to a secure folder with an encryption-based history log.

\- \*\*Restoration:\*\* Easily restore files from quarantine back to their original location.

\- \*\*Modern UI:\*\* Responsive sidebar, cross-fade transitions, and \*\*Dark Mode\*\* support.



\## 🏗️ Technical Architecture



The application is split into two layers:

1\. \*\*Frontend:\*\* GTK4 (C) handling the event loop, async dialogs, and asynchronous CSS rendering.

2\. \*\*Backend:\*\* A Windows-native engine for traversal and scanning logic for speed.







\## 🛠️ Requirements \& Installation



\### Prerequisites

To build from source, you need \*\*MSYS2\*\* installed on Windows with the following packages:

\- `mingw-w64-x86\_64-gtk4`

\- `mingw-w64-x86\_64-toolchain`

\- `mingw-w64-x86\_64-cmake`

\- `mingw-w64-x86\_64-ninja`



\### Building the Project

1\. Clone the repository:

&nbsp;  ```bash

&nbsp;  git clone \[https://github.com/MysticFusion/FOS-Antivirus.git](https://github.com/MysticFusion/FOS-Antivirus.git)

&nbsp;  cd FOS-Antivirus

