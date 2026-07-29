import sys
import os
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QScreen

from gui import GibVPNApp, SettingsDialog, SubscriptionManagerDialog, ServerListDialog, PingSitesDialog


app = QApplication(sys.argv)
app.setStyle("Fusion")

window = GibVPNApp()

# Create a fake active subscription so dialogs have something to show
if not window.subscriptions:
    window.subscriptions.append({
        "name": "DemoSub",
        "url": "https://example.com/sub",
        "active": True,
        "states": {}
    })
    window.active_subscription_index = 0

# Ensure a subscription cache file exists for the demo subscription
sub_file = window._subscription_file(window.subscriptions[0])
if not os.path.exists(sub_file) and os.path.exists("decoded_sub.txt"):
    shutil.copy2("decoded_sub.txt", sub_file)

window.show()

output_dir = os.path.join(os.getcwd(), "screenshots")
os.makedirs(output_dir, exist_ok=True)


def grab(widget, filename):
    # widget.grab() renders the widget itself, so it works both on a real
    # display and under the offscreen platform (screen.grabWindow cannot).
    pixmap = widget.grab()
    path = os.path.join(output_dir, filename)
    pixmap.save(path)
    print(f"Saved: {path} ({pixmap.width()}x{pixmap.height()})")


def step_main():
    grab(window, "01_main.png")
    QTimer.singleShot(300, step_settings)


def step_settings():
    global settings_dlg
    settings_dlg = SettingsDialog(window)
    settings_dlg.show()
    QTimer.singleShot(300, lambda: grab(settings_dlg, "02_settings.png"))
    QTimer.singleShot(700, step_subscriptions)


def step_subscriptions():
    global sub_dlg
    sub_dlg = SubscriptionManagerDialog(window, settings_dlg)
    sub_dlg.show()
    QTimer.singleShot(300, lambda: grab(sub_dlg, "03_subscriptions.png"))
    QTimer.singleShot(700, step_servers)


def step_servers():
    global srv_dlg
    srv_dlg = ServerListDialog(window)
    srv_dlg.show()
    QTimer.singleShot(300, lambda: grab(srv_dlg, "04_servers.png"))
    QTimer.singleShot(700, step_ping)


def step_ping():
    global ping_dlg
    ping_dlg = PingSitesDialog(window)
    ping_dlg.show()
    QTimer.singleShot(300, lambda: grab(ping_dlg, "05_ping_sites.png"))
    QTimer.singleShot(700, finish)


def finish():
    print("All screenshots saved to:", output_dir)
    app.quit()


QTimer.singleShot(500, step_main)
sys.exit(app.exec())
