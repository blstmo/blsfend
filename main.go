package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"
)

const (
    CONFIG_DIR  = "/etc/blsfend"
    DB_PATH     = "/etc/blsfend/blsfend.db"
    CONFIG_FILE = "/etc/blsfend/config.json"
    VERSION     = "1.0.0"
)

type Config struct {
    DiscordWebhook string            `json:"discord_webhook"`
    SlackWebhook   string            `json:"slack_webhook"`
    Commands       map[string]Rule    `json:"commands"`
    Groups        []ProtectionGroup  `json:"groups"`
}

type Rule struct {
    RequireAdmin bool     `json:"require_admin"`
    Requires2FA  bool     `json:"requires_2fa"`
    AllowGroups []string  `json:"allow_groups"`
    DenyGroups  []string  `json:"deny_groups"`
    TimeRestrict []string `json:"time_restrict"`
    Pattern     string    `json:"pattern"`
}

type ProtectionGroup struct {
    Name     string   `json:"name"`
    Users    []string `json:"users"`
    Commands []string `json:"commands"`
}

type User struct {
    Username string
    Secret   string
    IsAdmin  bool
    Groups   []string
}

type AuditLog struct {
    Timestamp time.Time
    Username  string
    Command   string
    Args      string
    Success   bool
    Reason    string
}

func initDB() (*sql.DB, error) {
    if err := os.MkdirAll(CONFIG_DIR, 0755); err != nil {
        return nil, fmt.Errorf("failed to create config directory: %v", err)
    }

    db, err := sql.Open("sqlite3", DB_PATH)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %v", err)
    }

    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            secret TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            groups TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            command TEXT,
            args TEXT,
            success BOOLEAN,
            reason TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);
    `)
    return db, err
}

func sendNotification(config Config, log AuditLog) {
    if config.DiscordWebhook != "" {
        sendDiscordNotification(config.DiscordWebhook, log)
    }
    if config.SlackWebhook != "" {
        sendSlackNotification(config.SlackWebhook, log)
    }
}

func sendDiscordNotification(webhook string, log AuditLog) {
    color := 65280 // Green
    if !log.Success {
        color = 16711680 // Red
    }

    embed := map[string]interface{}{
        "embeds": []map[string]interface{}{
            {
                "title": "Command Execution Alert",
                "description": fmt.Sprintf("Command: %s %s", log.Command, log.Args),
                "color": color,
                "fields": []map[string]interface{}{
                    {"name": "User", "value": log.Username, "inline": true},
                    {"name": "Status", "value": fmt.Sprintf("%v", log.Success), "inline": true},
                    {"name": "Reason", "value": log.Reason, "inline": true},
                    {"name": "Time", "value": log.Timestamp.Format(time.RFC3339), "inline": true},
                },
            },
        },
    }

    jsonData, _ := json.Marshal(embed)
    http.Post(webhook, "application/json", bytes.NewBuffer(jsonData))
}

func sendSlackNotification(webhook string, log AuditLog) {
    color := "good"
    if !log.Success {
        color = "danger"
    }

    message := map[string]interface{}{
        "attachments": []map[string]interface{}{
            {
                "color": color,
                "title": "Command Execution Alert",
                "text":  fmt.Sprintf("Command: %s %s", log.Command, log.Args),
                "fields": []map[string]interface{}{
                    {"title": "User", "value": log.Username, "short": true},
                    {"title": "Status", "value": fmt.Sprintf("%v", log.Success), "short": true},
                    {"title": "Reason", "value": log.Reason, "short": true},
                    {"title": "Time", "value": log.Timestamp.Format(time.RFC3339), "short": true},
                },
            },
        },
    }

    jsonData, _ := json.Marshal(message)
    http.Post(webhook, "application/json", bytes.NewBuffer(jsonData))
}

func checkTimeRestriction(timeRules []string) bool {
    if len(timeRules) == 0 {
        return true
    }

    now := time.Now()
    weekday := now.Weekday().String()[:3]
    
    for _, rule := range timeRules {
        parts := strings.Split(rule, ":")
        if len(parts) != 2 {
            continue
        }

        days := strings.Split(parts[0], "-")
        times := strings.Split(parts[1], "-")
        
        if len(times) != 2 {
            continue
        }

        startTime, _ := time.Parse("15:04", times[0])
        endTime, _ := time.Parse("15:04", times[1])
        
        if (len(days) == 1 && days[0] == weekday) ||
           (len(days) == 2 && isWeekdayInRange(weekday, days[0], days[1])) {
            currentTime := time.Date(0, 1, 1, now.Hour(), now.Minute(), 0, 0, time.UTC)
            if currentTime.After(startTime) && currentTime.Before(endTime) {
                return true
            }
        }
    }
    
    return false
}

func isWeekdayInRange(current, start, end string) bool {
    days := []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
    currentIdx := -1
    startIdx := -1
    endIdx := -1

    for i, day := range days {
        if day == current {
            currentIdx = i
        }
        if day == start {
            startIdx = i
        }
        if day == end {
            endIdx = i
        }
    }

    if startIdx <= currentIdx && currentIdx <= endIdx {
        return true
    }
    if startIdx > endIdx && (currentIdx >= startIdx || currentIdx <= endIdx) {
        return true
    }
    return false
}

func validateCommand(config Config, cmd string, args []string, user User) (bool, string) {
    rule, exists := config.Commands[cmd]
    if !exists {
        return true, "Command not restricted"
    }

    if rule.RequireAdmin && !user.IsAdmin {
        return false, "Admin privileges required"
    }

    if len(rule.AllowGroups) > 0 {
        allowed := false
        for _, group := range user.Groups {
            for _, allowedGroup := range rule.AllowGroups {
                if group == allowedGroup {
                    allowed = true
                    break
                }
            }
        }
        if !allowed {
            return false, "User not in allowed groups"
        }
    }

    for _, group := range rule.DenyGroups {
        for _, userGroup := range user.Groups {
            if group == userGroup {
                return false, "User in denied group"
            }
        }
    }

    if !checkTimeRestriction(rule.TimeRestrict) {
        return false, "Command not allowed at this time"
    }

    return true, "Allowed"
}

func executeCommand(cmd string, args []string) error {
    realCmd := exec.Command("/usr/bin/real/"+cmd, args...)
    realCmd.Stdin = os.Stdin
    realCmd.Stdout = os.Stdout
    realCmd.Stderr = os.Stderr

    realCmd.SysProcAttr = &syscall.SysProcAttr{}

    return realCmd.Run()
}

func main() {
    initCmd := flag.String("init", "", "Initialize system with Discord webhook URL")
    addUser := flag.String("add", "", "Add new user")
    makeAdmin := flag.Bool("admin", false, "Make user admin (use with -add)")
    addGroup := flag.String("group", "", "Add user to group (use with -add)")
    listUsers := flag.Bool("list", false, "List all users")
    showLogs := flag.Bool("logs", false, "Show audit logs")
    version := flag.Bool("version", false, "Show version")
    flag.Parse()

    if *version {
        fmt.Printf("BLSfend version %s (Linux)\n", VERSION)
        return
    }

    db, err := initDB()
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

	if *initCmd != "" {
        defaultConfig := Config{
            DiscordWebhook: *initCmd,
            Commands: map[string]Rule{
                "rm": {
                    Requires2FA: true,
                    TimeRestrict: []string{"Mon-Fri:09:00-17:00"},
                    Pattern: `^[^/].*`,
                },
                "chmod": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "chown": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "dd": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "mv": {
                    Requires2FA: true,
                },
                "systemctl": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "passwd": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "kill": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "pkill": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "service": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "shutdown": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "reboot": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "init": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "mount": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "umount": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "fdisk": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "mkfs": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "cryptsetup": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "apt": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "apt-get": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "yum": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "dnf": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "pacman": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "snap": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "dpkg": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
                "rpm": {
                    RequireAdmin: true,
                    Requires2FA: true,
                },
            },
            Groups: []ProtectionGroup{
                {
                    Name: "sysadmin",
                    Commands: []string{"chmod", "chown", "dd", "systemctl", "mount", "umount"},
                },
                {
                    Name: "pkgadmin",
                    Commands: []string{"apt", "apt-get", "yum", "dnf", "pacman", "snap", "dpkg", "rpm"},
                },
            },
        }

        jsonData, _ := json.MarshalIndent(defaultConfig, "", "    ")
        if err := os.WriteFile(CONFIG_FILE, jsonData, 0600); err != nil {
            log.Fatal("Failed to save config:", err)
        }
        fmt.Println("System initialized!")
        return
    }

    if *addUser != "" {
        secret, err := totp.Generate(totp.GenerateOpts{
            Issuer:      "BLSfend",
            AccountName: *addUser,
        })
        if err != nil {
            log.Fatal(err)
        }

        groups := []string{}
        if *addGroup != "" {
            groups = append(groups, *addGroup)
        }
        groupsJSON, _ := json.Marshal(groups)

        _, err = db.Exec("INSERT INTO users (username, secret, is_admin, groups) VALUES (?, ?, ?, ?)",
            *addUser, secret.Secret(), *makeAdmin, string(groupsJSON))
        if err != nil {
            log.Fatal("Failed to add user:", err)
        }

        fmt.Printf("User added! TOTP Secret: %s\n", secret.Secret())
        fmt.Println("Scan this QR code with your authenticator app:")
        url := secret.URL()
        qr, _ := exec.Command("qrencode", "-t", "UTF8", url).Output()
        fmt.Println(string(qr))
        return
    }

    if *listUsers {
        rows, err := db.Query("SELECT username, is_admin, groups FROM users")
        if err != nil {
            log.Fatal(err)
        }
        defer rows.Close()

        fmt.Println("Users:")
        for rows.Next() {
            var username string
            var isAdmin bool
            var groupsJSON string
            rows.Scan(&username, &isAdmin, &groupsJSON)
            fmt.Printf("- %s (Admin: %v, Groups: %s)\n", username, isAdmin, groupsJSON)
        }
        return
    }

    if *showLogs {
        rows, err := db.Query(`
            SELECT timestamp, username, command, args, success, reason 
            FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT 50
        `)
        if err != nil {
            log.Fatal(err)
        }
        defer rows.Close()

        fmt.Println("Recent Activity:")
        for rows.Next() {
            var log AuditLog
            rows.Scan(&log.Timestamp, &log.Username, &log.Command, &log.Args,
                &log.Success, &log.Reason)
            fmt.Printf("[%s] %s ran '%s %s' (%v: %s)\n",
                log.Timestamp.Format(time.RFC3339), log.Username,
                log.Command, log.Args, log.Success, log.Reason)
        }
        return
    }

    cmd := filepath.Base(os.Args[0])
    configData, err := os.ReadFile(CONFIG_FILE)
    if err != nil {
        log.Fatal("Config not found. Run with -init first")
    }

    var config Config
    if err := json.Unmarshal(configData, &config); err != nil {
        log.Fatal("Invalid config:", err)
    }

    currentUser, err := user.Current()
    if err != nil {
        log.Fatal("Failed to get current user:", err)
    }

    var dbUser User
    var groupsJSON string
    err = db.QueryRow(`
        SELECT username, secret, is_admin, groups 
        FROM users 
        WHERE username = ?`, currentUser.Username).Scan(
        &dbUser.Username, &dbUser.Secret, &dbUser.IsAdmin, &groupsJSON)
    if err != nil {
        log.Fatal("User not authorized")
    }
    json.Unmarshal([]byte(groupsJSON), &dbUser.Groups)

    args := flag.Args()
    allowed, reason := validateCommand(config, cmd, args, dbUser)
    if !allowed {
        log.Fatal("Command not allowed: ", reason)
    }

    rule := config.Commands[cmd]
    if rule.Requires2FA {
        fmt.Print("Enter 2FA code: ")
        var code string
        fmt.Scanln(&code)

        if valid := totp.Validate(code, dbUser.Secret); !valid {
            log.Fatal("Invalid 2FA code")
        }
    }

    err = executeCommand(cmd, args)
    success := err == nil

    logEntry := AuditLog{
        Timestamp: time.Now(),
        Username:  currentUser.Username,
        Command:   cmd,
        Args:      strings.Join(args, " "),
        Success:   success,
        Reason:    reason,
    }

    _, err = db.Exec(`
        INSERT INTO audit_log (timestamp, username, command, args, success, reason)
        VALUES (?, ?, ?, ?, ?, ?)`,
        logEntry.Timestamp, logEntry.Username, logEntry.Command,
        logEntry.Args, logEntry.Success, logEntry.Reason)
    if err != nil {
        log.Printf("Failed to log execution: %v", err)
    }

    // Send notification
    sendNotification(config, logEntry)

    if !success {
        os.Exit(1)
    }
}