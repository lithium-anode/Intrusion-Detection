import tkinter as tk
from tkinter import ttk
import threading
import subprocess
import os
import signal

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Intrusion Detection System")
        self.geometry("1000x650")
        self.configure(bg="#0a0c1a")

        self.frames = {}
        for F in (HomePage, IDSPage, AlertsPage):
            page_name = F.__name__
            frame = F(parent=self, controller=self)
            self.frames[page_name] = frame
            frame.place(x=0, y=0, relwidth=1, relheight=1)

        self.show_frame("HomePage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

        # Update alerts every time AlertsPage is shown
        if page_name == "AlertsPage":
            frame.update_alerts()


class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#0a0c1a")
        self.controller = controller

        panel = tk.Frame(self, bg="#0a0c1a")
        panel.place(x=450, y=250, width=400, height=300)

        title = tk.Label(panel, text="Dashboard", font=("Segoe UI", 28, "bold"), fg="#FFFFFF", bg="#0a0c1a")
        title.pack(pady=(20, 40))

        btn = tk.Button(panel, text="Intrusion Detection", command=lambda: controller.show_frame("IDSPage"),
                        width=25, font=("Segoe UI", 16),
                        bg="#0a0c1a", fg="#FFFFFF", activebackground="#333333", relief="flat")
        btn.pack()


class IDSPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#0a0c1a")
        self.controller = controller
        self.ids_process = None

        title = tk.Label(self, text="Intrusion Detection System", font=("Segoe UI", 32, "bold"),
                         fg="#FFFFFF", bg="#0a0c1a")
        title.place(x=380, y=30)

        # Histogram canvas
        self.hist_canvas = tk.Canvas(self, width=800, height=300, bg="#0a0c1a", highlightthickness=2, highlightbackground="white")
        self.hist_canvas.place(x=230, y=150)

        self.bar_colors = {
            "ICMP Flooding": "#00ffff",
            "SYN Scan": "#ff00ff",
            "Shellshock": "#ff3333",
            "XSS Attack": "#ffcc00"
        }

        self.spinner = ttk.Label(self, text="", font=("Segoe UI", 14), background="#0a0c1a", foreground="#00ff00")
        self.spinner.place(x=400, y=500)

        button_frame = tk.Frame(self, bg="#0a0c1a")
        button_frame.place(x=150, y=540)

        self.create_button(button_frame, "Run IDS", self.run_ids).pack(side=tk.LEFT, padx=10)
        self.create_button(button_frame, "Stop IDS", self.stop_ids).pack(side=tk.LEFT, padx=10)
        self.create_button(button_frame, "Back to Dashboard", lambda: controller.show_frame("HomePage")).pack(side=tk.LEFT, padx=10)
        self.create_button(button_frame, "View Alerts", lambda: controller.show_frame("AlertsPage")).pack(side=tk.LEFT, padx=10)


    def create_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, width=18, font=("Segoe UI", 14), bg="#0a0c1a", fg="#FFFFFF", activebackground="#333333", relief="flat")

    def run_ids(self):
        self.spinner.config(text="Running IDS...")

        def execute_and_load():
            try:
                self.ids_process = subprocess.Popen(["sudo", "/absolute/path/to/executable"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.ids_process.wait()

                attack_counts = {
                    "ICMP Flooding": 0,
                    "SYN Scan": 0,
                    "Shellshock": 0,
                    "XSS Attack": 0
                }

                with open("alerts.log", "r") as log_file:
                    for line in log_file:
                        if "ICMP Flooding" in line:
                            attack_counts["ICMP Flooding"] += 1
                        elif "SYN Scan" in line:
                            attack_counts["SYN Scan"] += 1
                        elif "Shellshock" in line:
                            attack_counts["Shellshock"] += 1
                        elif "XSS" in line:
                            attack_counts["XSS Attack"] += 1

                self.update_histogram(attack_counts)

            except FileNotFoundError:
                self.hist_canvas.create_text(400, 150, text="alerts.log not found", fill="white", font=("Segoe UI", 16, "bold"))
            except subprocess.CalledProcessError as e:
                self.hist_canvas.create_text(400, 150, text=f"Failed to run IDS: {e}", fill="white", font=("Segoe UI", 16, "bold"))
            except Exception as e:
                self.hist_canvas.create_text(400, 150, text=f"Unexpected error: {e}", fill="white", font=("Segoe UI", 16, "bold"))
            finally:
                self.spinner.config(text="")

        threading.Thread(target=execute_and_load, daemon=True).start()

    def stop_ids(self):
        if self.ids_process and self.ids_process.poll() is None:
            self.ids_process.send_signal(signal.SIGINT)
            self.spinner.config(text="Stopping IDS...")

    def update_histogram(self, data):
        self.hist_canvas.delete("all")
        max_value = max(data.values()) if data else 1
        bar_height = 40
        spacing = 30
        x_start = 250

        for i, (attack, count) in enumerate(data.items()):
            y = i * (bar_height + spacing)
            bar_id = self.hist_canvas.create_rectangle(x_start, y, x_start, y + bar_height,
                                                       fill=self.bar_colors[attack], width=0)
            label = f"{attack}: {count}"
            self.hist_canvas.create_text(20, y + bar_height // 2, anchor="w", text=label,
                                         fill="white", font=("Segoe UI", 14, "bold"))
            self.animate_bar(bar_id, x_start, y, count, max_value)

    def animate_bar(self, bar_id, x_start, y, count, max_value):
        target_width = int((count / max_value) * 400) if max_value else 0
        current_width = 0

        def grow():
            nonlocal current_width
            if current_width < target_width:
                current_width += 5
                self.hist_canvas.coords(bar_id, x_start, y, x_start + current_width, y + 40)
                self.after(10, grow)

        grow()


class AlertsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#0a0c1a")
        self.controller = controller

        title = tk.Label(self, text="Alerts Log", font=("Segoe UI", 28, "bold"),
                         fg="#FFFFFF", bg="#0a0c1a")
        title.pack(pady=30)

        self.alert_box = tk.Text(self, wrap="word", height=20, width=100, bg="#1a1c2c", fg="#FFFFFF",
                                 insertbackground="white", font=("Consolas", 12), borderwidth=0)
        self.alert_box.pack(pady=10)

        back_btn = tk.Button(self, text="Back to IDS", command=lambda: controller.show_frame("IDSPage"),
                             width=20, font=("Segoe UI", 14), bg="#0a0c1a", fg="#FFFFFF", activebackground="#333333", relief="flat")
        back_btn.pack(pady=10)

        self.update_alerts()

    def update_alerts(self):
        try:
            with open("alerts.log", "r") as log_file:
                content = log_file.read()
                self.alert_box.delete(1.0, tk.END)
                self.alert_box.insert(tk.END, content)
        except FileNotFoundError:
            self.alert_box.insert(tk.END, "alerts.log not found.")


if __name__ == "__main__":
    app = App()
    app.mainloop()