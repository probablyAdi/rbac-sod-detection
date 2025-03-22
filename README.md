# RBAC SoD & UPE Detection System

## Overview
This project is designed to **automate the detection of Segregation of Duties (SoD) conflicts** and **Unauthorized Privilege Escalation (UPE)** within a **Role-Based Access Control (RBAC) system**. It efficiently analyzes user-role mappings, role hierarchies, and privilege assignments to detect policy violations, ensuring compliance with security regulations.

## Key Features
- ✔️**Dynamic Analysis:** The system processes role hierarchies, privilege assignments, and toxic action rules to detect SoD conflicts and privilege escalations.
- ✔️**Automated SoD & UPE Detection:** Identifies security risks by analyzing role privileges and user assignments.
- ✔️**Structured Output:** Generates a detailed report in `analysis_result.csv` summarizing violations.
- ✔️**Optimized Performance:** Implemented with multi-threading and efficient data structures for fast processing.
- ✔️**Dockerized Deployment:** Easily deployable in a containerized environment for scalability.

## How It Works
1. **Input Files:**
   - `roles.csv` (To be provided by the user) - Contains user-role mappings.
   - `privileges.csv` - Defines which privileges are assigned to each role.
   - `role_hierarchy.csv` - Specifies role inheritance relationships.
   - `sod_rules.csv` - Lists toxic combinations of privileges that violate SoD policies.
   - `toxic_actions.csv` - Defines critical actions that should not be combined under any user.

2. **Processing:**
   - The system reads the input files and constructs an RBAC model.
   - It traverses role hierarchies to resolve inherited permissions.
   - It applies SoD rules to detect conflicting privilege assignments.
   - It flags cases of unauthorized privilege escalation (UPE).

3. **Output:**
   - The final analysis results, including detected SoD violations and UPE cases, are stored in `analysis_result.csv`.

## Usage Instructions
### Running via Docker
1. **Build the Docker Image:**
   ```sh
   docker build -t rbac-sod-detection .
   ```
2. **Run the Container:**
   ```sh
   docker run --rm -v $(pwd):/app rbac-sod-detection
   ```
   - Ensure that all necessary input files are present in the working directory.
   - The output will be generated in `analysis_result.csv`.

## Why This Matters
Organizations using ERP and role-based systems face challenges in managing **user access risks**. Manually tracking **toxic combinations** and **escalated privileges** is time-consuming and error-prone. This tool automates that process, enhancing security, auditability, and compliance with access control policies.

## 📌 Notes for Users
- You **must** provide your own `roles.csv` file (or an equivalent Excel file) containing user-role mappings.
- The system will analyze your provided data and output violations to `analysis_result.csv`.

---

This project ensures robust security enforcement in RBAC systems, preventing unauthorized privilege escalations and policy violations. 🚀

