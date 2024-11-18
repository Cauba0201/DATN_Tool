import subprocess
import re


def ping(domain):
    # Khởi tạo tiến trình với subprocess.Popen để ping trong thời gian thực
    process = subprocess.Popen(['ping', '-n', '10', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    packets_sent = None
    packet_loss = None
    avg_latency = None

    print(f"Đang ping {domain}...")

    # Đọc từng dòng đầu ra khi tiến trình đang chạy
    for line in process.stdout:
        print(line.strip())  # Hiển thị từng dòng của kết quả ping ngay lập tức

        # Dùng biểu thức chính quy để tìm thông tin cần thiết từ mỗi dòng
        if "Packets: Sent" in line:
            packets_sent = re.search(r"Packets: Sent = (\d+)", line)
            packets_sent = packets_sent.group(1) if packets_sent else "N/A"

        if "loss" in line:
            packet_loss = re.search(r"(\d+)% loss", line)
            packet_loss = packet_loss.group(1) if packet_loss else "N/A"

        if "Average" in line:
            avg_latency = re.search(r"Average = (\d+ms)", line)
            avg_latency = avg_latency.group(1) if avg_latency else "N/A"

    # Đợi tiến trình kết thúc
    process.wait()

    # Trả về kết quả cuối cùng sau khi hoàn tất quá trình ping
    packets_sent = packets_sent if packets_sent else "N/A"
    packet_loss = packet_loss if packet_loss else "N/A"
    avg_latency = avg_latency if avg_latency else "N/A"

    return packets_sent, packet_loss, avg_latency


# Ví dụ sử dụng
domain = "103.15.51.160"
packets_sent, packet_loss, avg_latency = ping(domain)
print(f"Kết quả cho {domain}:")
print(f"Số gói đã gửi: {packets_sent}")
print(f"Tỷ lệ mất gói: {packet_loss}%")
print(f"Độ trễ trung bình: {avg_latency}")
