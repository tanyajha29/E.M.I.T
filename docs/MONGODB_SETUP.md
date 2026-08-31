# MongoDB Environment Setup Guide

This guide describes how to configure and connect the database for E.M.I.T. (Evidence-backed Mobile Investigation Tool) using either a local MongoDB installation or MongoDB Atlas (cloud).

---

## Option A: Local MongoDB Server

To run MongoDB on your local workstation:

1.  **Download MongoDB Community Server**:
    Download the Windows MSI installer from the [MongoDB Download Center](https://www.mongodb.com/try/download/community).
2.  **Run the Installer**:
    *   Follow the setup wizard.
    *   Select **"Complete"** setup.
    *   Keep **"Run service as Network Service user"** enabled (this automatically runs MongoDB as a background system service).
    *   *(Optional)* Install MongoDB Compass (a GUI client for browsing database collections).
3.  **Verify local server runs**:
    Open a PowerShell console and run:
    ```powershell
    # Standard local connection check
    mongosh --eval "db.adminCommand('ping')"
    ```
4.  **Configure environment variables**:
    Add the local connection URI to your `backend/.env` file:
    ```env
    MONGODB_URI=mongodb://localhost:27017
    MONGODB_DATABASE=emit
    ```

---

## Option B: MongoDB Atlas (Cloud Database)

If you prefer to host your data in the cloud (recommended for remote collaboration or if you do not want to install databases locally):

1.  **Create an Atlas Account**:
    Register for a free account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
2.  **Create a Project & Cluster**:
    *   Create a new project named `E.M.I.T.`.
    *   Deploy a new database cluster. Select the **"M0 (Free)"** shared tier.
    *   Choose a cloud provider and region close to you (e.g., AWS, Azure, or GCP).
3.  **Configure Database User Access**:
    *   Navigate to **Security -> Database Access**.
    *   Add a new database user.
    *   Choose **"Password"** authentication.
    *   Assign the user the **"Read and write to any database"** role.
    *   Keep note of the username and password!
4.  **Configure Network Security (IP Allowlist)**:
    *   Navigate to **Security -> Network Access**.
    *   Click **"Add IP Address"**.
    *   Select **"Allow Access From Anywhere"** (IP `0.0.0.0/0`) for development speed, or add your current host IP address to restrict access securely.
5.  **Copy the Connection String**:
    *   Go to **Deployment -> Database**.
    *   Click **"Connect"** on your cluster.
    *   Select **"Drivers"** (Python).
    *   Copy the connection string. It will look like:
        `mongodb+srv://<username>:<password>@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority`
6.  **Configure environment variables**:
    Add this connection string to your local `backend/.env` file, replacing `<username>` and `<password>` with the database credentials you created in Step 3:
    ```env
    MONGODB_URI=mongodb+srv://db_user_emit:your_strong_password@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority
    MONGODB_DATABASE=emit
    ```

---

## Critical Security Guidelines

> [!CAUTION]
> **Never commit credentials to version control!**
> *   Do **NOT** hardcode your MongoDB Atlas connection string anywhere in the application source code.
> *   Do **NOT** commit `backend/.env` containing active passwords or Atlas connection strings. The repository `.gitignore` is configured to ignore `.env` files.
> *   Only modify/commit `backend/.env.example` as a template placeholder.
