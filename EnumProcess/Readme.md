# Process Enumeration in Windows

- Process enumeration, the art of systematically identifying and tracking running processes within a target system. For the red teamer, it represents the critical first step towards gaining a foothold in the host environment. It allows for the precise selection of processes to interact, providing the means to execute various actions, from injecting code to maintaining persistence. 
- Windows API function EnumProcesses belongs to API lib. **Psapi.h**
- It retrieves the process identifier (PID) for each running process in the system.
- Code’s overall flow is like a security guard checking who is in each office:
  <br>
  it lists all office numbers (EnumProcesses), then for each office it “opens” the door (OpenProcess), checks the person’s name badge         (GetModuleBaseName), and compares it to the target name (e.g. "svchost.exe"). <br>
- If it finds a match, it reports the office number (PID) and stops. Useful in a defensive context to understand how malware might perform reconnaissance – by enumerating processes to find a specific service or application – and to ensure we know how to monitor such behavior. (In fact, attackers often use EnumProcesses to scan a system as a first step

---

## Overview
Windows processes are like "active programs" running on your system.  
Process enumeration is the act of **listing and identifying these processes** programmatically.  

This is useful for :
- **System monitoring** (defensive tools).  
- **Threat analysis** (detecting suspicious processes).  
- **Learning attacker behavior** (attackers also enumerate processes before injecting payloads).  

---

## Analogy
Think of your Windows system as a **large office building**:

- **`EnumProcesses`** → the security guard writes down all the **room numbers** (Process IDs).  
- **`OpenProcess`** → the guard unlocks a specific room.  
- **`EnumProcessModules`** → he looks at the **documents on the desk** (modules inside the process).  
- **`GetModuleBaseName`** → he reads the **title of the main document** (process name).  
- **Comparison** → checks if the room is the one he’s searching for (e.g., `"svchost.exe"`).  
- **`CloseHandle`** → closes the door after inspection.  

This repeats until the target process is found.

---

##  Step-by-Step Algorithm

1. **Call `EnumProcesses`**  
   - Retrieves all running process IDs (PIDs).  

2. **Loop through each PID**  
   - If PID = 0 → skip.  
   - Otherwise, continue.  

3. **OpenProcess**  
   - Tries to open the process using access rights.  
   - If fails → continue.  

4. **EnumProcessModules**  
   - Gets the list of modules loaded in the process.  

5. **GetModuleBaseName**  
   - Reads the main executable’s name (e.g., `"svchost.exe"`).  

6. **Compare with target**  
   - If name matches → store PID + handle.  
   - If not, close handle and continue.  

7. **CloseHandle**  
   - Always close after checking.

## NOTE: Run the compiler as administrator to get expected & matching results

## Algorithm Flowchart
```mermaid
flowchart TD
    A[Start] --> B[EnumProcesses → Get PIDs]
    B --> C[Calculate number of PIDs]
    C --> D[Loop through each PID]
    D -->|PID = 0| E[Skip & continue]
    D -->|Else| F[OpenProcess]
    F -->|Fail| E
    F -->|Success| G[EnumProcessModules]
    G -->|Fail| H[CloseHandle → Continue]
    G -->|Success| I[GetModuleBaseName]
    I -->|Fail| H
    I -->|Success| J[Compare with target]
    J -->|Match| K[Store PID & Handle → Return]
    J -->|No Match| H
    H --> D
    K --> L[End]


