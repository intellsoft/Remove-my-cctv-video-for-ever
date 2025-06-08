<p align="right">
⚠️ <b>هشدار:</b> این نرم‌افزار اطلاعات را به صورت غیرقابل بازگشت پاک می‌کند. لطفاً با نهایت احتیاط استفاده کنید. مسئولیت هرگونه استفاده، مجاز یا غیرمجاز، بر عهده کاربر است. ⚠️
</p\>

# 🔐 پاک‌سازی ایمن اطلاعات (Secure Eraser) 🗑️

این نرم‌افزار قدرتمند به شما کمک می‌کند تا اطلاعات حساس خود، از جمله **فیلم‌های دوربین مداربسته (DVR/NVR)** و سایر فایل‌ها و پوشه‌ها را به صورت ایمن و غیرقابل بازیابی پاک کنید.

## 🌟 قابلیت‌ها

  * **پاک‌سازی ایمن فایل‌ها و پوشه‌ها:** حذف دائمی اطلاعات با استفاده از متدهای پیشرفته.
  * **پشتیبانی از متدهای مختلف پاک‌سازی:**
      * **Simple Overwrite (1-pass):** بازنویسی یک‌باره با داده‌های تصادفی برای امنیت پایه و سرعت بالا.
      * **NIST 800-88 (3-pass):** استاندارد امنیتی معتبر با سه مرحله بازنویسی تصادفی.
      * **Gutmann (35-pass):** سی‌و‌پنج مرحله بازنویسی با الگوهای پیچیده برای امنیت فوق‌العاده بالا.
  * **شناسایی و انتخاب آسان:**
      * انتخاب فایل‌ها و پوشه‌ها از طریق رابط کاربری.
      * قابلیت کشیدن و رها کردن (Drag & Drop) فایل‌ها و پوشه‌ها.
      * شناسایی خودکار پارتیشن‌های استاندارد.
      * قابلیت ویژه **"شناسایی هارد DVR/NVR"** برای کاربران ویندوز (نیاز به دسترسی مدیر).
  * **رابط کاربری دوستانه:** محیط گرافیکی ساده و قابل فهم با نمایش وضعیت پیشرفت.
  * **گزارش عملیات:** ارائه گزارش کامل از فایل‌های پاک شده و خطاهای احتمالی.
  * **اجرا با دسترسی مدیر (Administrator):** توصیه می‌شود برای عملکرد کامل، به خصوص برای شناسایی و حذف درایوها، برنامه را با دسترسی مدیر اجرا کنید.

## 🖥️ راهنمای استفاده از قابلیت پاک‌سازی فیلم‌های DVR/NVR

برای پاک‌سازی فیلم‌های دوربین مداربسته که معمولاً روی هاردهای DVR/NVR ذخیره می‌شوند، مراحل زیر را دنبال کنید:

1.  **اتصال هارد:** هارد DVR/NVR خود را به کامپیوتر متصل کنید.
2.  **اجرای برنامه با دسترسی مدیر:** برنامه `Secure Eraser` را با راست کلیک و انتخاب "Run as administrator" اجرا کنید.
3.  **شناسایی هارد DVR:** روی دکمه "شناسایی هارد DVR/NVR (مخصوص ویندوز)" کلیک کنید. این قابلیت تنها در ویندوز موجود است.
4.  **مشاهده اطلاعات هارد:** یک پنجره اطلاعاتی باز می‌شود که لیست هاردهای فیزیکی متصل به سیستم شما را نمایش می‌دهد. اگر هارد DVR شما پارتیشن قابل خواندن توسط ویندوز نداشته باشد (مثلاً فرمت ext4 لینوکس)، تعداد پارتیشن‌های آن صفر نمایش داده می‌شود.
5.  **دسترسی به فایل‌ها (مهم):** برای دسترسی به فایل‌های این هاردها در ویندوز، باید نرم‌افزار جانبی مانند **Ext2Fsd** یا **Paragon Linux File Systems for Windows** را نصب کنید تا یک نام درایو (مثلاً E:) به آن اختصاص یابد.
6.  **انتخاب و پاک‌سازی:** پس از نصب این ابزارها و مشاهده درایو در ویندوز، می‌توانید از دکمه "انتخاب پوشه" برای انتخاب پوشه حاوی فیلم‌های دوربین مداربسته و شروع عملیات پاک‌سازی ایمن استفاده کنید.

## 🛠️ نصب و اجرا

این نرم‌افزار با پایتون ۳ و PyQt5 توسعه یافته است.

1.  **نصب پیش‌نیازها:**
    ```bash
    pip install PyQt5 psutil
    ```
2.  **اجرا:**
    ```bash
    python delete.py
    ```
    (توصیه می‌شود در ویندوز با دسترسی مدیر اجرا شود.)

-----

\<p align="left"\>
⚠️ \<b\>Warning:\</b\> This software irrevocably erases data. Please use with extreme caution. The user is solely responsible for any authorized or unauthorized use. ⚠️
\</p\>

# 🔐 Secure Eraser 🗑️

This powerful software helps you securely and irreversibly erase sensitive data, including **CCTV (DVR/NVR) footage**, and other files and folders.

## 🌟 Features

  * **Secure File and Folder Deletion:** Permanently erase data using advanced methods.
  * **Multiple Erasing Methods Supported:**
      * **Simple Overwrite (1-pass):** One-pass random data overwrite for basic security and high speed.
      * **NIST 800-88 (3-pass):** A recognized security standard with three random overwrite passes.
      * **Gutmann (35-pass):** Thirty-five passes with complex patterns for extremely high security.
  * **Easy Detection and Selection:**
      * Select files and folders via the user interface.
      * Drag & Drop functionality for files and folders.
      * Automatic detection of standard partitions.
      * Special feature for **"DVR/NVR Hard Drive Detection"** for Windows users (requires administrator access).
  * **User-Friendly Interface:** Simple and intuitive graphical environment with progress display.
  * **Operation Report:** Provides a comprehensive report of successfully erased files and any errors.
  * **Run as Administrator:** It is recommended to run the application with administrator privileges for full functionality, especially for drive detection and deletion.

## 🖥️ How to Erase DVR/NVR Footage

To erase CCTV footage typically stored on DVR/NVR hard drives, follow these steps:

1.  **Connect the Hard Drive:** Connect your DVR/NVR hard drive to your computer.
2.  **Run as Administrator:** Right-click on the `Secure Eraser` application and choose "Run as administrator".
3.  **Detect DVR Hard Drive:** Click the "Detect DVR/NVR Hard Drive (Windows Only)" button. This feature is only available on Windows.
4.  **View Drive Information:** An information window will pop up, listing the physical hard drives connected to your system. If your DVR hard drive does not have a readable partition by Windows (e.g., Linux ext4 format), its partition count will show as zero.
5.  **Accessing Files (Important):** To access files on these hard drives in Windows, you must install third-party software such as **Ext2Fsd** or **Paragon Linux File Systems for Windows** to assign a drive letter (e.g., E:).
6.  **Select and Erase:** After installing these tools and seeing the drive appear in Windows, you can use the "Select Folder" button to choose the folder containing the CCTV footage and begin the secure erasure process.

## 🛠️ Installation and Execution

This software is developed using Python 3 and PyQt5.

1.  **Install Prerequisites:**
    ```bash
    pip install PyQt5 psutil
    ```
2.  **Run:**
    ```bash
    python delete.py
    ```
    (It is recommended to run as administrator on Windows.)

-----

### 👨‍💻 Developed by: Mohammadali Abbaspour

Specialized CCTV Software

🔗 Visit my website: [Intellsoft.ir](https://intellsoft.ir)

-----