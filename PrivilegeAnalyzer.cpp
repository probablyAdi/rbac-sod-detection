#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <set>
#include <thread>
#include <mutex>

using namespace std;

struct Role {
    set<string> privileges;
};

unordered_map<string, Role> roleMap;
unordered_map<string, set<string>> userRoles;
unordered_map<string, set<string>> roleHierarchy;
set<pair<string, string>> sodViolations;
set<string> toxicPrivileges;
mutex resultsMutex;

void skipCSVHeader(ifstream &file) {
    string header;
    getline(file, header);
}

void loadSoDRules(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error: Could not open " << filename << endl;
        exit(1);
    }
    skipCSVHeader(file);
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string role1, role2;
        getline(ss, role1, ',');
        getline(ss, role2, ',');
        sodViolations.insert({role1, role2});
    }
    file.close();
}

void loadToxicPrivileges(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error: Could not open " << filename << endl;
        exit(1);
    }
    skipCSVHeader(file);
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string privilege;
        getline(ss, privilege, ',');
        toxicPrivileges.insert(privilege);
    }
    file.close();
}

void loadPrivilegesFromFile(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error: Could not open " << filename << endl;
        exit(1);
    }
    skipCSVHeader(file);
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string role, privileges;
        getline(ss, role, ',');
        getline(ss, privileges);
        stringstream privStream(privileges);
        string privilege;
        while (getline(privStream, privilege, ';')) {
            roleMap[role].privileges.insert(privilege);
        }
    }
    file.close();
}

void loadRoleHierarchy(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error: Could not open " << filename << endl;
        exit(1);
    }
    skipCSVHeader(file);
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string parent, child;
        getline(ss, parent, ',');
        getline(ss, child, ',');
        roleHierarchy[parent].insert(child);
    }
    file.close();
}

void analyzeRoleRecursive(const string& role, set<string>& accumulatedRoles, set<string>& accumulatedPrivileges) {
    if (accumulatedRoles.count(role)) return;
    accumulatedRoles.insert(role);
    if (roleMap.count(role)) {
        accumulatedPrivileges.insert(roleMap[role].privileges.begin(), roleMap[role].privileges.end());
    }
    if (roleHierarchy.count(role)) {
        for (const string& inherited : roleHierarchy[role]) {
            analyzeRoleRecursive(inherited, accumulatedRoles, accumulatedPrivileges);
        }
    }
}

set<string> checkUnauthorizedEscalation(const set<string>& privileges) {
    set<string> foundToxic;
    for (const string& priv : privileges) {
        if (toxicPrivileges.count(priv)) {
            foundToxic.insert(priv);
        }
    }
    return foundToxic;
}

set<pair<string, string>> checkSoDViolation(const set<string>& roles) {
    set<pair<string, string>> violations;
    for (const auto& pair : sodViolations) {
        if (roles.count(pair.first) && roles.count(pair.second)) {
            violations.insert(pair);
        }
    }
    return violations;
}

void analyzeUser(const string& userName, vector<string>& results) {
    set<string> accumulatedRoles, accumulatedPrivileges;
    for (const string& role : userRoles[userName]) {
        analyzeRoleRecursive(role, accumulatedRoles, accumulatedPrivileges);
    }
    set<string> toxicFound = checkUnauthorizedEscalation(accumulatedPrivileges);
    set<pair<string, string>> sodFound = checkSoDViolation(accumulatedRoles);
    
    if (!toxicFound.empty() || !sodFound.empty()) {
        stringstream result;
        result << userName << "," << (toxicFound.empty() ? "No" : "Yes") << ",";

        if (!toxicFound.empty()) {
            for (const auto& priv : toxicFound) result << priv << ";";
            string res = result.str();
            res.pop_back();
            result.str(""); result.clear(); result << res;
        }
        
        result << "," << (sodFound.empty() ? "No" : "Yes") << ",";

        if (!sodFound.empty()) {
            for (const auto& pair : sodFound) result << pair.first << "-" << pair.second << ";";
            string res = result.str();
            res.pop_back();
            result.str(""); result.clear(); result << res;
        }

        result << "\n";

        lock_guard<mutex> lock(resultsMutex);
        results.push_back(result.str());
    }
}

void loadRolesFromFile(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error: Could not open " << filename << endl;
        exit(1);
    }
    skipCSVHeader(file);
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string user, roles;
        getline(ss, user, ',');
        string role;
        while (getline(ss, role, ',')) {
            if (!role.empty()) userRoles[user].insert(role);
        }
    }
    file.close();
}

int main() {
    loadRolesFromFile("roles.csv");
    loadPrivilegesFromFile("privileges.csv");
    loadSoDRules("sod_rules.csv");
    loadToxicPrivileges("toxic_actions.csv");
    loadRoleHierarchy("role_hierarchy.csv");

    ofstream csvFile("analysis_result.csv");
    if (!csvFile) {
        cerr << "Error: Could not open output CSV file!" << endl;
        return 1;
    }
    csvFile << "User,Unauthorized Privilege Escalation,Toxic Privileges,SoD Violation,Conflicting Roles\n";

    vector<thread> threads;
    vector<string> results;
    for (const auto& [userName, _] : userRoles) {
        threads.emplace_back(analyzeUser, userName, ref(results));
    }
    for (auto& t : threads) t.join();
    for (const string& line : results) csvFile << line;
    
    csvFile.close();
    cout << "Analysis complete. Results saved to analysis_result.csv" << endl;
    return 0;
}
