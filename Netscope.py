import socket
import threading
import ipaddress
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


DEFAULT_PORTS = [22, 80, 443]
scan_cancel_event = threading.Event()


def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_result_text():
    return result_box.get("1.0", tk.END).strip()


def update_history(summary):
    history_listbox.insert(0, summary)
    if history_listbox.size() > 8:
        history_listbox.delete(tk.END)


def set_scan_controls_enabled(enabled):
    state = "normal" if enabled else "disabled"
    resolve_btn.config(state=state)
    copy_btn.config(state=state)
    export_btn.config(state=state)
    clear_btn.config(state=state)
    entry.config(state=state)
    ports_entry.config(state=state)
    cancel_btn.config(state="disabled" if enabled else "normal")


def resolve_addresses(hostname):
    addresses = []
    seen = set()

    for family, socktype, proto, canonname, sockaddr in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
        if family == socket.AF_INET:
            ip = sockaddr[0]
        elif family == socket.AF_INET6:
            ip = sockaddr[0]
        else:
            continue

        if ip in seen:
            continue

        seen.add(ip)
        addresses.append((ip, family))

    if not addresses:
        raise socket.gaierror()

    return addresses


def reverse_lookup(ip):
    try:
        host_name, alias_list, _ = socket.gethostbyaddr(ip)
        names = [host_name] + alias_list
        cleaned = []
        for name in names:
            if name and name not in cleaned:
                cleaned.append(name)
        return cleaned
    except Exception:
        return []


def query_whois_server(server, query_text, timeout=4):
    with socket.create_connection((server, 43), timeout=timeout) as whois_socket:
        whois_socket.sendall((query_text + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            data = whois_socket.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_whois_fields(raw_text):
    field_names = [
        "inetnum",
        "inet6num",
        "netrange",
        "orgname",
        "org-name",
        "organization",
        "netname",
        "descr",
        "country",
        "status",
        "cidr",
        "country",
        "origin",
        "asn",
        "abuse-mailbox",
        "admin-c",
        "tech-c",
        "mnt-by",
        "role",
        "address",
    ]
    values = {}

    for line in raw_text.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        normalized_key = key.strip().lower()
        if normalized_key in field_names:
            values.setdefault(normalized_key, [])
            cleaned_value = value.strip()
            if cleaned_value and cleaned_value not in values[normalized_key]:
                values[normalized_key].append(cleaned_value)

    return values


def get_whois_summary(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return ["WHOIS: invalid IP address"]

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return ["WHOIS: not available for private/local address"]

    try:
        referral_text = query_whois_server("whois.iana.org", ip)
        referral_server = None
        for line in referral_text.splitlines():
            if line.lower().startswith("refer:"):
                referral_server = line.split(":", 1)[1].strip()
                break

        if not referral_server:
            return ["WHOIS: referral server not found"]

        whois_text = query_whois_server(referral_server, ip)
        fields = parse_whois_fields(whois_text)

        summary_lines = []
        org_name = fields.get("orgname", []) + fields.get("org-name", []) + fields.get("organization", [])
        net_name = fields.get("netname", [])
        inet_range = fields.get("inetnum", []) + fields.get("inet6num", []) + fields.get("netrange", []) + fields.get("cidr", [])
        country = fields.get("country", [])
        origin = fields.get("origin", [])
        asn = fields.get("asn", [])
        status = fields.get("status", [])
        abuse_mailbox = fields.get("abuse-mailbox", [])
        address = fields.get("address", [])
        descr = fields.get("descr", [])
        mnt_by = fields.get("mnt-by", [])
        role = fields.get("role", [])
        admin_c = fields.get("admin-c", [])
        tech_c = fields.get("tech-c", [])

        summary_lines.append(f"WHOIS Server: {referral_server}")

        if org_name:
            summary_lines.append(f"WHOIS Org: {', '.join(org_name[:3])}")
        else:
            summary_lines.append("WHOIS Org: not published")

        if net_name:
            summary_lines.append(f"WHOIS Netname: {', '.join(net_name[:3])}")
        if inet_range:
            summary_lines.append(f"WHOIS Range/CIDR: {', '.join(inet_range[:3])}")

        if country:
            summary_lines.append(f"WHOIS Country: {', '.join(country[:3])}")
        else:
            summary_lines.append("WHOIS Country: not published")

        if origin:
            summary_lines.append(f"WHOIS Origin: {', '.join(origin[:3])}")
        if asn:
            summary_lines.append(f"WHOIS ASN: {', '.join(asn[:3])}")
        if status:
            summary_lines.append(f"WHOIS Status: {', '.join(status[:3])}")
        if abuse_mailbox:
            summary_lines.append(f"WHOIS Abuse: {', '.join(abuse_mailbox[:3])}")
        if address:
            summary_lines.append(f"WHOIS Address: {', '.join(address[:2])}")
        if descr:
            summary_lines.append(f"WHOIS Description: {', '.join(descr[:2])}")
        if mnt_by:
            summary_lines.append(f"WHOIS Maintainer: {', '.join(mnt_by[:2])}")
        if role:
            summary_lines.append(f"WHOIS Role: {', '.join(role[:2])}")
        if admin_c:
            summary_lines.append(f"WHOIS Admin-C: {', '.join(admin_c[:2])}")
        if tech_c:
            summary_lines.append(f"WHOIS Tech-C: {', '.join(tech_c[:2])}")

        if len(summary_lines) == 1:
            summary_lines.append("WHOIS: no useful registry fields published")

        return summary_lines
    except Exception:
        return ["WHOIS lookup unavailable"]


def build_scan_report(hostname, ports):
    scan_time = current_timestamp()
    resolved_addresses = resolve_addresses(hostname)
    primary_ip = resolved_addresses[0][0]

    lines = [
        f"Scan time: {scan_time}",
        f"Target: {hostname}",
        "",
        f"Primary IP: {primary_ip}",
        "",
        "All resolved IPs:",
    ]

    for ip, family in resolved_addresses:
        family_label = "IPv6" if family == socket.AF_INET6 else "IPv4"
        lines.append(f"  - {ip} ({family_label})")
        reverse_names = reverse_lookup(ip)
        if reverse_names:
            lines.append(f"    Reverse DNS: {', '.join(reverse_names)}")
        else:
            lines.append("    Reverse DNS: not found")

        whois_lines = get_whois_summary(ip)
        for whois_line in whois_lines:
            lines.append(f"    {whois_line}")

    lines.append("")
    lines.append("TCP port scan:")

    for ip, family in resolved_addresses:
        if scan_cancel_event.is_set():
            lines.append("")
            lines.append("Scan cancelled by user.")
            break

        lines.append(f"")
        family_label = "IPv6" if family == socket.AF_INET6 else "IPv4"
        lines.append(f"Target IP: {ip} ({family_label})")
        for port in ports:
            if scan_cancel_event.is_set():
                lines.append("  - Scan cancelled before remaining ports were checked.")
                break

            with socket.socket(family, socket.SOCK_STREAM) as scanner:
                scanner.settimeout(0.8)
                status_code = scanner.connect_ex((ip, port))

            status = "open" if status_code == 0 else "closed"
            lines.append(f"  - Port {port}: {status}")

        if scan_cancel_event.is_set():
            break

    return "\n".join(lines), scan_time


def finish_scan(result_text, scan_time, hostname, ports_count):
    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, result_text + "\n")
    result_box.config(state="disabled")
    update_history(f"{scan_time} | {hostname} | ports: {ports_count}")
    if scan_cancel_event.is_set():
        status_var.set("Scan cancelled")
    else:
        status_var.set("Lookup and scan completed")
    set_scan_controls_enabled(True)
    scan_cancel_event.clear()


def finish_scan_with_error(message, status_text):
    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, message + "\n")
    result_box.config(state="disabled")
    status_var.set(status_text)
    set_scan_controls_enabled(True)
    scan_cancel_event.clear()


def run_scan_worker(hostname, ports):
    try:
        result_text, scan_time = build_scan_report(hostname, ports)
    except socket.gaierror:
        root.after(0, lambda: finish_scan_with_error(f"Could not resolve hostname: {hostname}", "Resolution failed"))
        return
    except Exception as e:
        root.after(0, lambda: finish_scan_with_error(f"Error: {e}", "Error occurred"))
        return

    root.after(0, lambda: finish_scan(result_text, scan_time, hostname, len(ports)))


def normalize_target(target_text):
    target = target_text.strip()
    for prefix in ("http://", "https://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0]
    return target


def parse_ports(port_text):
    port_text = port_text.strip()
    if not port_text:
        return DEFAULT_PORTS[:]

    ports = set()
    for chunk in port_text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start_port = int(start_text.strip())
            end_port = int(end_text.strip())
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            for port in range(start_port, end_port + 1):
                ports.add(port)
        else:
            ports.add(int(chunk))

    return sorted(ports) if ports else DEFAULT_PORTS[:]


def lookup_and_scan():
    hostname = normalize_target(entry.get())
    if not hostname:
        messagebox.showwarning("Input needed", "Please enter a hostname.")
        return

    try:
        ports = parse_ports(ports_entry.get())
    except ValueError:
        messagebox.showwarning("Invalid ports", "Enter ports as comma-separated values or ranges, like 22,80,443 or 20-25.")
        return

    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, f"Scanning {hostname}...\n")
    result_box.config(state="disabled")
    status_var.set("Scanning in progress...")
    scan_cancel_event.clear()
    set_scan_controls_enabled(False)

    scan_thread = threading.Thread(target=run_scan_worker, args=(hostname, ports), daemon=True)
    scan_thread.start()


def cancel_scan():
    scan_cancel_event.set()
    status_var.set("Cancelling scan...")
    cancel_btn.config(state="disabled")


def clear_fields():
    entry.delete(0, tk.END)
    ports_entry.delete(0, tk.END)
    ports_entry.insert(0, "22,80,443")
    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)
    result_box.config(state="disabled")
    status_var.set("Ready")
    entry.focus()


def copy_results():
    result_text = get_result_text()
    if not result_text:
        messagebox.showinfo("Copy results", "There are no results to copy yet.")
        return

    root.clipboard_clear()
    root.clipboard_append(result_text)
    root.update_idletasks()
    status_var.set("Results copied to clipboard")


def export_results():
    result_text = get_result_text()
    if not result_text:
        messagebox.showinfo("Export results", "There are no results to export yet.")
        return

    file_path = filedialog.asksaveasfilename(
        title="Save scan results",
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), (
            "All files", "*.*")],
        initialfile=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    )
    if not file_path:
        return

    with open(file_path, "w", encoding="utf-8") as output_file:
        output_file.write(result_text + "\n")

    status_var.set("Results exported")


# --- UI setup ---
root = tk.Tk()
root.title("DNS Lookup and Port Scanner")
root.geometry("620x640")
root.minsize(620, 640)
root.resizable(True, True)

main_frame = ttk.Frame(root, padding=16)
main_frame.pack(fill="both", expand=True)

title_label = ttk.Label(main_frame, text="DNS Lookup + Port Scanner", font=("Segoe UI", 16, "bold"))
title_label.pack(pady=(0, 4))

subtitle_label = ttk.Label(
    main_frame,
    text="Resolve a hostname, scan selected TCP ports, and save or copy the report.",
    foreground="#555555",
)
subtitle_label.pack(pady=(0, 14))

input_frame = ttk.Frame(main_frame)
input_frame.pack(fill="x")

entry_label = ttk.Label(input_frame, text="Hostname:")
entry_label.pack(side="left")

entry = ttk.Entry(input_frame, width=30)
entry.pack(side="left", padx=(8, 0), fill="x", expand=True)
entry.focus()

ports_frame = ttk.Frame(main_frame)
ports_frame.pack(fill="x", pady=(10, 0))

ports_label = ttk.Label(ports_frame, text="TCP Ports:")
ports_label.pack(side="left")

ports_entry = ttk.Entry(ports_frame, width=30)
ports_entry.pack(side="left", padx=(8, 0), fill="x", expand=True)
ports_entry.insert(0, "22,80,443")
ports_entry.bind("<Return>", lambda event: lookup_and_scan())

ports_hint = ttk.Label(main_frame, text="Use comma-separated ports or ranges like 20-25", foreground="#555555")
ports_hint.pack(fill="x", pady=(4, 0))

entry.bind("<Return>", lambda event: lookup_and_scan())

button_frame = ttk.Frame(main_frame)
button_frame.pack(fill="x", pady=12)

resolve_btn = ttk.Button(button_frame, text="Lookup & Scan", command=lookup_and_scan)
resolve_btn.pack(side="left", padx=(0, 8))

copy_btn = ttk.Button(button_frame, text="Copy Output", command=copy_results)
copy_btn.pack(side="left", padx=(0, 8))

export_btn = ttk.Button(button_frame, text="Save Report", command=export_results)
export_btn.pack(side="left", padx=(0, 8))

clear_btn = ttk.Button(button_frame, text="Clear", command=clear_fields)
clear_btn.pack(side="left")

cancel_btn = ttk.Button(button_frame, text="Cancel Scan", command=cancel_scan, state="disabled")
cancel_btn.pack(side="left", padx=(8, 0))

result_box = tk.Text(main_frame, height=10, wrap="word", state="disabled",
                      bg="#f5f5f5", relief="flat", padx=8, pady=8)
result_box.pack(fill="both", expand=True)

history_frame = ttk.Frame(main_frame)
history_frame.pack(fill="both", expand=False, pady=(12, 0))

history_label = ttk.Label(history_frame, text="Recent Scans")
history_label.pack(anchor="w")

history_inner = ttk.Frame(history_frame)
history_inner.pack(fill="both", expand=True, pady=(4, 0))

history_scrollbar = ttk.Scrollbar(history_inner, orient="vertical")
history_scrollbar.pack(side="right", fill="y")

history_listbox = tk.Listbox(
    history_inner,
    height=6,
    relief="flat",
    bg="#fbfbfb",
    yscrollcommand=history_scrollbar.set,
)
history_listbox.pack(side="left", fill="both", expand=True)
history_scrollbar.config(command=history_listbox.yview)

status_var = tk.StringVar(value="Ready")
status_bar = ttk.Label(main_frame, textvariable=status_var, anchor="w",
                        foreground="#555555")
status_bar.pack(fill="x", pady=(8, 0))

root.mainloop()