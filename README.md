
```markdown
<p align="center">
  <img src="https://raw.githubusercontent.com/loveis2s/NetSpecter/main/assets/logo.png" alt="NetSpecter Logo" width="200"/>
</p>

<h1 align="center">NetSpecter</h1>

<p align="center">
  <img src="https://img.shields.io/github/license/loveis2s/NetSpecter?style=for-the-badge&color=blueviolet" alt="License"/>
  <img src="https://img.shields.io/github/stars/loveis2s/NetSpecter?style=for-the-badge&color=yellow" alt="Stars"/>
  <img src="https://img.shields.io/github/forks/loveis2s/NetSpecter?style=for-the-badge&color=blue" alt="Forks"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blueviolet?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python"/>
  <img src="https://img.shields.io/github/last-commit/loveis2s/NetSpecter?style=for-the-badge&color=green" alt="Last Commit"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/WinDivert-Driver-red?style=flat-square" alt="WinDivert"/>
  <img src="https://img.shields.io/badge/Scapy-Packets-orange?style=flat-square" alt="Scapy"/>
  <img src="https://img.shields.io/badge/PyQt6-GUI-blueviolet?style=flat-square" alt="PyQt6"/>
  <img src="https://img.shields.io/badge/DPI-Deep%20Inspection-critical?style=flat-square" alt="DPI"/>
</p>

<p align="center">
  <b>Инструмент для фильтрации трафика, блокировки сайтов и управления прокси.</b><br>
  <sub>Для изолированных лабораторных сред. Не для использования во внешних сетях.</sub>
</p>

---

## 📖 Языки / Languages

- [Русский](#-русская-версия)
- [English](#-english-version)

---

# 🇷🇺 Русская версия

## 📋 Содержание

- [Что это?](#-что-это)
- [Скриншоты](#-скриншоты)
- [Возможности](#-возможности)
- [Установка](#-установка)
- [Запуск](#-запуск)
- [Как пользоваться](#-как-пользоваться)
- [Настройки](#-настройки)
- [FAQ](#-faq)
- [Предупреждение](#-предупреждение)

---

## 🤔 Что это?

**NetSpecter** — программа для перехвата и фильтрации сетевого трафика на твоём компьютере. Она умеет:

- Блокировать сайты (YouTube, Google и любые другие).
- Обрывать QUIC-соединения (чтобы браузер не мог обойти блокировку).
- Скачивать и проверять списки прокси.
- Привязывать прокси к отдельным программам.
- Обходить блокировки в играх.

Всё управляется через простой графический интерфейс.

---

## 📸 Скриншоты

<p align="center">
  <img src="https://raw.githubusercontent.com/loveis2s/NetSpecter/main/assets/screenshot_dpi.png" alt="DPI Tab" width="400"/>
  <img src="https://raw.githubusercontent.com/loveis2s/NetSpecter/main/assets/screenshot_proxy.png" alt="Proxy Tab" width="400"/>
</p>

> *Если картинки не грузятся — положи свои скриншоты в папку `assets/` и назови так же.*

---

## 🔥 Возможности

| Функция | Описание |
|---------|----------|
| **DPI-блокировка** | Перехват TLS/QUIC пакетов и мгновенный обрыв соединения (RST-инжект) |
| **QUIC-спуфинг** | Подмена UDP-пакетов на TCP SYN — браузер падает в ошибку |
| **Прокси-менеджер** | Загрузка из 12 источников, проверка в 50 потоков, фильтр по странам |
| **Привязка к процессам** | Каждая программа может идти через свой прокси |
| **Игровой обход** | Добавление серверов (IP:Port) для обхода банов |
| **Автозагрузка** | Сама добавляется в реестр Windows |
| **Тёмная тема** | Фиолетово-синий GUI, приятный глазу |

---

## 💿 Установка

### 1. Установи Python

Скачай с [python.org](https://python.org) версию 3.8 или новее. При установке поставь галочку **"Add Python to PATH"**.

### 2. Установи зависимости

Открой командную строку (Win+R → `cmd`) и введи:

```bash
pip install PyQt6 scapy pydivert
```

### 3. Установи Npcap (только Windows)

Скачай с [npcap.com](https://npcap.com/#download) и установи. Обязательно отметь галочку:
- ✅ **"Install Npcap in WinPcap API-compatible Mode"**

### 4. Скачай NetSpecter

```bash
git clone https://github.com/loveis2s/NetSpecter.git
cd NetSpecter
```

Или просто скачай ZIP с GitHub и распакуй.

---

## ▶️ Запуск

### Способ 1: BAT-файл (рекомендуется)

Просто запусти `launcher.bat` — он сам запросит права администратора и запустит программу.

### Способ 2: Командная строка

```bash
# Запусти cmd от имени администратора
cd C:\путь\к\NetSpecter
python osn.py
```

### Способ 3: Linux

```bash
sudo python osn.py
```

---

## 📚 Как пользоваться

### Блокировка сайтов

1. Открой вкладку **DPI**.
2. Введи домен (например, `youtube.com`) в поле ввода.
3. Нажми **Add**.
4. Нажми **Start Engine**.
5. Попробуй открыть YouTube в браузере — он не загрузится.

### Прокси

1. Открой вкладку **Proxy**.
2. Нажми **Download Proxies** — программа скачает списки из интернета.
3. Нажми **Check All** — проверит, какие работают.
4. Рабочие отобразятся зелёным цветом.
5. Нажми **Export Working**, чтобы сохранить их в файл.

### Привязка к процессу

1. Открой вкладку **Process Binding**.
2. Выбери процесс из списка.
3. Выбери рабочий прокси из выпадающего списка.
4. Нажми **Assign**.
5. Теперь эта программа будет ходить через выбранный прокси.

### Игровые серверы

1. Открой вкладку **Games**.
2. Введи IP и порт сервера.
3. Нажми **Add**.
4. Включи галку **Enable Game IP Spoofing**.

---

## ⚙️ Настройки

| Настройка | Где находится | Что делает |
|-----------|---------------|------------|
| Автозагрузка | Вкладка Settings | Запускает программу вместе с Windows |
| QUIC-спуфинг | Вкладка DPI | Включает/выключает подмену UDP→TCP |
| Макс. прокси | Вкладка Proxy | Сколько прокси хранить в базе |
| Таймаут | Вкладка Proxy | Время ожидания ответа от прокси |
| Тестовый URL | Вкладка Settings | Ссылка для проверки прокси |

Все настройки сохраняются в `C:\Users\ТВОЙ_ПОЛЬЗОВАТЕЛЬ\.xtech_netspecter\`.

---

## ❓ FAQ

### Почему YouTube не блокируется?

1. Убедись, что запустил программу **от имени администратора**.
2. Проверь, что Npcap установлен в **WinPcap API-compatible Mode**.
3. Убедись, что домен `youtube.com` добавлен во вкладке DPI.
4. Нажми **Start Engine**.

### Почему прокси не проверяются?

Проверь, что у тебя есть интернет. Смени тестовый URL в настройках, если `httpbin.org` недоступен.

### Это вирус?

Нет. Это программа с открытым исходным кодом. Ты можешь посмотреть каждую строчку кода.

### Работает ли на Windows 7?

Нет. Требуется Windows 10 или новее.

---

## ⚠️ Предупреждение

> **Эта программа создана для образовательных целей.**  
> Используй её только в изолированной лабораторной среде.  
> Автор не несёт ответственности за использование программы в нарушение законов.

---

# 🇬🇧 English Version

## 📋 Table of Contents

- [What is it?](#-what-is-it)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Settings](#-settings)
- [FAQ](#-faq-1)
- [Disclaimer](#-disclaimer)

---

## 🤔 What is it?

**NetSpecter** is a network traffic filtering and proxy management tool. It can:

- Block websites using DPI (Deep Packet Inspection).
- Terminate QUIC connections.
- Download and verify proxy lists from multiple sources.
- Bind proxies to specific processes.
- Bypass game server bans.

Everything is controlled through a simple GUI.

---

## 🔥 Features

| Feature | Description |
|---------|-------------|
| **DPI Blocking** | TLS/QUIC packet interception with instant RST injection |
| **QUIC Spoofing** | UDP → TCP SYN substitution |
| **Proxy Manager** | Download from 12 sources, verify with 50 threads, filter by country |
| **Process Binding** | Assign different proxies to different programs |
| **Game Spoofing** | Randomize IP for game servers |
| **Auto-start** | Windows Registry integration |
| **Dark Theme** | Purple-blue GUI, easy on the eyes |

---

## 💿 Installation

### 1. Install Python

Download from [python.org](https://python.org). Check **"Add Python to PATH"**.

### 2. Install dependencies

```bash
pip install PyQt6 scapy pydivert
```

### 3. Install Npcap (Windows only)

Download from [npcap.com](https://npcap.com/#download). Check:
- ✅ **"Install Npcap in WinPcap API-compatible Mode"**

### 4. Download NetSpecter

```bash
git clone https://github.com/loveis2s/NetSpecter.git
cd NetSpecter
```

---

## ▶️ Usage

### Method 1: BAT file (recommended)

Run `launcher.bat` — it will request admin rights and start the program.

### Method 2: Command line

```bash
# Run cmd as Administrator
cd C:\path\to\NetSpecter
python osn.py
```

### Blocking websites

1. Open **DPI** tab.
2. Enter a domain (e.g., `youtube.com`).
3. Click **Add**.
4. Click **Start Engine**.
5. Try opening YouTube — it will not load.

### Proxies

1. Open **Proxy** tab.
2. Click **Download Proxies**.
3. Click **Check All**.
4. Working proxies appear in green.
5. Click **Export Working** to save them.

---

## ❓ FAQ

### Why is YouTube not blocked?

1. Make sure you run as **Administrator**.
2. Npcap must be installed in **WinPcap API-compatible Mode**.
3. Domain must be added in the DPI tab.
4. Click **Start Engine**.

### Is this a virus?

No. It's open source. You can read every line of code.

---

## ⚠️ Disclaimer

> **This tool is for educational purposes only.**  
> Use it only in isolated lab environments.  
> The author is not responsible for any misuse.

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Made with 💜 by <a href="https://github.com/loveis2s">loveis2s</a></sub>
</p>
```
