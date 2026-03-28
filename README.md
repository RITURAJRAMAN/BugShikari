# BugShikari 🕷️🎯

<p align="center">
  <img src="https://img.shields.io/badge/Beginner-Friendly-green.svg" alt="Beginner Friendly">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Status-Active-red.svg" alt="Status">
</p>

## 👋 What is BugShikari?

Imagine you are a security guard hired to check if a building is safe. You have to check every door, every window, see
if the alarm works, and check if anyone left their keys under the doormat. Doing this manually for a huge castle (a big
website like Google or Facebook) would take forever!

**BugShikari** is your robot assistant. It automatically runs around the building, checks all the locks, looks for
hidden entrances, and reads the notes left by the builders to see if they made any mistakes.

In technical terms, it is an **automated reconnaissance and vulnerability scanner**. It helps "Bug Hunters" (people who
find security flaws for money) find weak spots in websites without doing all the boring work manually.

---

## ⚡ Why Use This?

* **For Beginners:** It teaches you *what* to look for. By reading the reports it generates, you learn about different
  types of security bugs.
* **For Pros:** It saves hours of time. While you drink coffee ☕, BugShikari gathers all the data you need to start
  hacking.
* **It's Safe:** It performs "Passive" and "Non-Intrusive" scans mostly. It doesn't break the website; it just looks at
  it very closely.

---

## 🔍 How Does It Work?

BugShikari works in 4 simple steps:

1. **Mapping the Area (Subdomain Enumeration)**:
    * It finds all the different sections of a website (like `shop.example.com`, `admin.example.com`).
2. **Checking the Rules (Security Headers & CSP)**:
    * It looks at the security rules the website has set up. Are they strict? Or did they forget to lock the front door?
3. **Hunting for Secrets (JS Analysis & Dorks)**:
    * It reads the computer code (JavaScript) that the website sends to your browser to see if the developers
      accidentally left passwords or "API keys" inside.
4. **Generating the Report**:
    * It creates a beautiful HTML file that looks like a report card, showing you everything it found, graded by how
      dangerous it is (Critical, High, Medium, Low).

---

## 🛠️ How to Install (Step-by-Step)

You need to have **Python** installed on your computer. If you don't have it, download it
from [python.org](https://www.python.org/).

1. **Download this tool**:
    * Click the green "Code" button above and choose "Download ZIP", then unzip it.
    * OR run this command in your terminal:
      ```bash
      git clone https://github.com/yourusername/BugShikari.git
      ```

2. **Open your Terminal/Command Prompt**:
    * Go into the folder where you downloaded BugShikari.
      ```bash
      cd BugShikari
      ```

3. **Install the requirements**:
    * BugShikari needs some helper tools (libraries) to work. Install them with:
      ```bash
      pip install -r requirements.txt
      ```

---

## 🚀 How to Use It

Using BugShikari is very easy. You just tell it which website to scan.

### 1. The Basic Scan (Recommended)

This runs all the checks and generates a report.

```bash
python main.py --target example.com
```

### 2. Run Specific Modules

If you only want to run a specific test (like checking for open redirects):

```bash
python main.py --target example.com --module 8
```

### 3. Generate Report Only

If you have already run scans and just want to re-generate the HTML report:

```bash
python main.py --report
```

### 4. The Interactive Mode

If you don't like typing long commands, just run:

```bash
python main.py
```

It will ask you nicely what you want to do!

### 5. See the Report

After the scan finishes, go to the `results` folder. You will see a file like `report_example_com_....html`.
Double-click it to open it in your browser!

---

## 📚 What Checks Does It Run? (The Technical Stuff)

For those who want to know exactly what's happening under the hood:

* **Subdomain Discovery**: Finds hidden parts of the site.
* **Security Headers**: Checks if the site protects users from common attacks (XSS, Clickjacking).
* **CSP Analysis**: Checks if the Content Security Policy is strong enough.
* **CORS Scanner**: Checks if the site accidentally lets other bad sites read its data.
* **JavaScript Secrets**: Scans code for accidental leaks of passwords/keys.
* **Open Redirects**: Checks if the site can be used to trick users into going to a fake site.
* **Tech Fingerprinting**: Guesses what software the site is running (WordPress, React, etc.).

---

## ⚠️ Important Warning

**Only use this on websites you have permission to test!**

* **Authorized:** Your own website, or companies with "Bug Bounty Programs" (like Google, Facebook, etc.).
* **Unauthorized:** Your neighbor's blog, your school's website (unless they said yes). **This is illegal.**

**Be a Shikari (Hunter), not a criminal.** 🕵️‍♂️

---

**BugShikari** by **Rituraj Raman**
*Make the web safer, one bug at a time.*
