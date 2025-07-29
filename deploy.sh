#!/bin/bash

# Script để tự động hóa việc khởi tạo Git và đẩy dự án lên GitHub.
# Dừng ngay lập tức nếu có lệnh nào thất bại.
set -e

# --- Cấu hình ---
GIT_REPO_URL="git@github.com:ankynguyen163/netscanner.git"
COMMIT_MESSAGE="Initial commit of NetScanner project"

# --- Hàm tiện ích màu mè ---
echo_green() {
    echo -e "\033[0;32m$1\033[0m"
}

echo_red() {
    echo -e "\033[0;31m$1\033[0m"
}

# --- Script chính ---

echo_green "Bắt đầu quá trình triển khai dự án lên GitHub..."

# 1. Kiểm tra xem git đã được cài đặt chưa
if ! command -v git &> /dev/null
then
    echo_red "Lỗi: Git chưa được cài đặt. Vui lòng cài đặt Git và thử lại."
    exit 1
fi

# 2. Khởi tạo kho chứa Git nếu chưa có
if [ ! -d ".git" ]; then
    echo_green "-> Khởi tạo kho chứa Git mới..."
    git init
else
    echo_green "-> Kho chứa Git đã tồn tại."
fi

# 3. Tạo file .gitignore (đã được cung cấp ở trên)
echo_green "-> Đảm bảo file .gitignore đã tồn tại và đúng nội dung..."
# (Giả sử bạn đã tạo file .gitignore từ bước 1)
if [ ! -f ".gitignore" ]; then
    echo_red "Lỗi: Không tìm thấy file .gitignore. Vui lòng tạo file này trước."
    exit 1
fi

# 4. Thêm remote repository nếu chưa có
if ! git remote -v | grep -q "origin.*$GIT_REPO_URL"; then
    # Kiểm tra xem remote 'origin' đã tồn tại chưa
    if git remote | grep -q "origin"; then
        echo_green "-> Remote 'origin' đã tồn tại, đang cập nhật URL..."
        git remote set-url origin "$GIT_REPO_URL"
    else
        echo_green "-> Thêm remote 'origin'..."
        git remote add origin "$GIT_REPO_URL"
    fi
else
    echo_green "-> Remote 'origin' đã được cấu hình."
fi

# 5. Thêm tất cả các file vào staging
echo_green "-> Thêm tất cả các file vào staging area..."
git add .

# 6. Commit các thay đổi
echo_green "-> Commit các thay đổi..."
git commit -m "$COMMIT_MESSAGE" || echo "Thông báo: Không có gì mới để commit."

# 7. Đổi tên nhánh thành 'main'
echo_green "-> Đảm bảo nhánh hiện tại là 'main'..."
git branch -M main

# 8. Đẩy code lên kho chứa từ xa
echo_green "-> Đẩy các thay đổi lên kho chứa từ xa (origin/main)..."
git push -u origin main

echo_green "✅ Hoàn tất! Dự án của bạn đã được đẩy lên GitHub thành công."