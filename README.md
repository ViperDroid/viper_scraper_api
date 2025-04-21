## 📦 Building the Executable

You can create a standalone executable from the Python script using PyInstaller. This bundles your script and its dependencies (like CustomTkinter) into a single package that can be run without installing Python or the required libraries separately.

**❗ IMPORTANT OS Note:**

*   PyInstaller **builds an executable for the operating system you are currently using.**
*   To create a **Windows executable (`.exe`)**, you **MUST** run the `pyinstaller` command on a **Windows machine**.
*   Running `pyinstaller` on **Linux (like Kali)** will create a **Linux executable**, which will **NOT** run on Windows.

**Steps:**

1.  **Set up the environment:**
    *   On the target OS (Windows for `.exe`, Linux for Linux executable), clone the repository, create/activate the virtual environment (`venv`), and install requirements (`pip install -r requirements.txt`).
    *   Install PyInstaller in the activated virtual environment:
        ```bash
        pip install pyinstaller
        ```

2.  **Run PyInstaller:**
    *   Navigate to the project directory (`viper-api`) in your terminal or command prompt.
    *   Execute the PyInstaller command. For a typical GUI application, this is recommended:
        ```bash
        # Use this command on WINDOWS to create a single .exe file for Windows
        # Use this command on LINUX to create a single executable file for Linux
        pyinstaller --onefile --windowed viper_scraper_exe.py
        ```
        *   `--onefile`: Bundles everything into a single file.
        *   `--windowed`: (Recommended for GUI apps like this one) Prevents a console/terminal window from appearing when the application runs. If your app *needs* a console, use `--console` or omit `--windowed`.

3.  **Locate the Executable:**
    *   PyInstaller creates the executable **locally** inside a new folder named `dist` within your project directory (`viper-api/dist/`).
    *   **On Windows:** Inside `dist`, you'll find `viper_scraper_exe.exe`.
    *   **On Linux:** Inside `dist`, you'll find `viper_scraper_exe` (usually without an extension).

4.  **Distribution:**
    *   Copy the executable file found in the `dist` folder to the machine where you want to run it (remembering it only runs on the OS type it was built on).
