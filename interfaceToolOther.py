import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import ttk


class FormMain:
    def __init__(self, root):
        self.root = root
        self.root.title("Ping Application")
        self.root.geometry("500x400")
        self.host_list = []  # Danh sách IP/Domain

        # Nút mở Form quản lý danh sách
        self.btn_manage_hosts = tk.Button(root, text="Quản lý danh sách", command=self.open_list_host_form, font=("Arial", 12))
        self.btn_manage_hosts.pack(pady=10)

        # Hiển thị danh sách các Host
        self.lst_hosts = tk.Listbox(root, height=15, width=50, font=("Courier", 12))
        self.lst_hosts.pack(pady=10)

        # Nút kiểm tra Ping
        self.btn_test = tk.Button(root, text="Kiểm tra Ping", command=self.test_hosts, font=("Arial", 12))
        self.btn_test.pack(pady=10)

    def open_list_host_form(self):
        form_list_host = FormListHost(self.root, self.host_list)
        self.root.wait_window(form_list_host.top)  # Chờ khi Form con đóng
        self.host_list = form_list_host.host_list  # Cập nhật danh sách
        self.update_host_display()

    def update_host_display(self):
        # Cập nhật Listbox hiển thị danh sách
        self.lst_hosts.delete(0, tk.END)
        for host in self.host_list:
            self.lst_hosts.insert(tk.END, host)

    def test_hosts(self):
        # Hiển thị danh sách sẽ kiểm tra
        if not self.host_list:
            messagebox.showinfo("Thông báo", "Không có địa chỉ nào để kiểm tra!")
            return

        for host in self.host_list:
            # Ở đây có thể thực hiện hàm kiểm tra ping với từng host
            print(f"Đang kiểm tra: {host}")
        messagebox.showinfo("Thông báo", "Kiểm tra hoàn tất!")


#### **Form quản lý danh sách: `FormListHost`**

class FormListHost:
    def __init__(self, parent, host_list):
        self.top = tk.Toplevel(parent)
        self.top.title("Quản lý danh sách")
        self.top.geometry("400x300")

        self.host_list = host_list.copy()  # Sao chép danh sách ban đầu

        # Listbox hiển thị danh sách
        self.lst_hosts = tk.Listbox(self.top, height=12, width=40, font=("Courier", 12))
        self.lst_hosts.pack(pady=10)

        # Cập nhật hiển thị ban đầu
        self.update_host_display()

        # Nút thêm
        self.btn_add = tk.Button(self.top, text="Thêm", command=self.add_host, font=("Arial", 10))
        self.btn_add.pack(side=tk.LEFT, padx=5)

        # Nút sửa
        self.btn_edit = tk.Button(self.top, text="Sửa", command=self.edit_host, font=("Arial", 10))
        self.btn_edit.pack(side=tk.LEFT, padx=5)

        # Nút xóa
        self.btn_delete = tk.Button(self.top, text="Xóa", command=self.delete_host, font=("Arial", 10))
        self.btn_delete.pack(side=tk.LEFT, padx=5)

        # Nút Lưu
        self.btn_save = tk.Button(self.top, text="Lưu và Đóng", command=self.save_and_close, font=("Arial", 10))
        self.btn_save.pack(side=tk.RIGHT, padx=5)

    def update_host_display(self):
        # Cập nhật Listbox hiển thị danh sách
        self.lst_hosts.delete(0, tk.END)
        for host in self.host_list:
            self.lst_hosts.insert(tk.END, host)

    def add_host(self):
        new_host = simpledialog.askstring("Thêm Host", "Nhập địa chỉ IP hoặc domain:")
        if new_host:
            self.host_list.append(new_host)
            self.update_host_display()

    def edit_host(self):
        selected_index = self.lst_hosts.curselection()
        if selected_index:
            current_host = self.host_list[selected_index[0]]
            new_host = simpledialog.askstring("Sửa Host", "Nhập địa chỉ mới:", initialvalue=current_host)
            if new_host:
                self.host_list[selected_index[0]] = new_host
                self.update_host_display()
        else:
            messagebox.showwarning("Chú ý", "Vui lòng chọn một Host để sửa!")

    def delete_host(self):
        selected_index = self.lst_hosts.curselection()
        if selected_index:
            del self.host_list[selected_index[0]]
            self.update_host_display()
        else:
            messagebox.showwarning("Chú ý", "Vui lòng chọn một Host để xóa!")

    def save_and_close(self):
        self.top.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FormMain(root)
    root.mainloop()