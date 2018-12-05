package main

import (
    "errors"
    "fmt"
    "net"
    "os"
    "regexp"
    "strings"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

const (
    db_user = "logcatcher"
    db_password = "password"
    db_address = "127.0.0.1"
    db_port = "3306"
    db_database = "log_data"
)

type db_row struct {
    syslog_agent *net.UDPAddr
    index int
    priority string
    version string
    time_stamp string
    hostname string
    app_name string
    proc_id string
    message_id string
    structured_data string
    sd_application string
    sd_bytes_from_client string
    sd_bytes_from_server string
    sd_connection_tag string
    sd_destination_address string
    sd_destination_interface_name string
    sd_destination_port string
    sd_destination_zone_name string
    sd_dst_nat_rule_name string
    sd_dst_nat_rule_type string
    sd_elapsed_time string
    sd_encrypted string
    sd_icmp_type string
    sd_message string
    sd_name string
    sd_nat_connection_tag string
    sd_nat_destination_address string
    sd_nat_destination_port string
    sd_nat_source_address string
    sd_nat_source_port string
    sd_nested_application string
    sd_packet_incoming_interface string
    sd_packets_from_client string
    sd_packets_from_server string
    sd_policy_name string
    sd_profile_name string
    sd_protocol_id string
    sd_reason string
    sd_roles string
    sd_routing_instance string
    sd_rule_name string
    sd_service_name string
    sd_session_id_32 string
    sd_source_address string
    sd_source_port string
    sd_source_zone_name string
    sd_src_nat_rule_name string
    sd_src_nat_rule_type string
    sd_username string
}

var ProtocolNumbers = map[string]string{
    "0" : "HOPOPT",
    "1" : "ICMP",
    "2" : "IGMP",
    "3" : "GGP",
    "4" : "IPv4",
    "5" : "ST",
    "6" : "TCP",
    "7" : "CBT",
    "8" : "EGP",
    "9" : "IGP",
    "10" : "BBN-RCC-MON",
    "11" : "NVP-II",
    "12" : "PUP",
    "13" : "ARGUS (deprecated)",
    "14" : "EMCON",
    "15" : "XNET",
    "16" : "CHAOS",
    "17" : "UDP",
    "18" : "MUX",
    "19" : "DCN-MEAS",
    "20" : "HMP",
    "21" : "PRM",
    "22" : "XNS-IDP",
    "23" : "TRUNK-1",
    "24" : "TRUNK-2",
    "25" : "LEAF-1",
    "26" : "LEAF-2",
    "27" : "RDP",
    "28" : "IRTP",
    "29" : "ISO-TP4",
    "30" : "NETBLT",
    "31" : "MFE-NSP",
    "32" : "MERIT-INP",
    "33" : "DCCP",
    "34" : "3PC",
    "35" : "IDPR",
    "36" : "XTP",
    "37" : "DDP",
    "38" : "IDPR-CMTP",
    "39" : "TP++",
    "40" : "IL",
    "41" : "IPv6",
    "42" : "SDRP",
    "43" : "IPv6-Route",
    "44" : "IPv6-Frag",
    "45" : "IDRP",
    "46" : "RSVP",
    "47" : "GRE",
    "48" : "DSR",
    "49" : "BNA",
    "50" : "ESP",
    "51" : "AH",
    "52" : "I-NLSP",
    "53" : "SWIPE (deprecated)",
    "54" : "NARP",
    "55" : "MOBILE",
    "56" : "TLSP",
    "57" : "SKIP",
    "58" : "IPv6-ICMP",
    "59" : "IPv6-NoNxt",
    "60" : "IPv6-Opts",
    "61" : "",
    "62" : "CFTP",
    "63" : "",
    "64" : "SAT-EXPAK",
    "65" : "KRYPTOLAN",
    "66" : "RVD",
    "67" : "IPPC",
    "68" : "",
    "69" : "SAT-MON",
    "70" : "VISA",
    "71" : "IPCV",
    "72" : "CPNX",
    "73" : "CPHB",
    "74" : "WSN",
    "75" : "PVP",
    "76" : "BR-SAT-MON",
    "77" : "SUN-ND",
    "78" : "WB-MON",
    "79" : "WB-EXPAK",
    "80" : "ISO-IP",
    "81" : "VMTP",
    "82" : "SECURE-VMTP",
    "83" : "VINES",
    "84" : "TTP/IPTM",
    "85" : "NSFNET-IGP",
    "86" : "DGP",
    "87" : "TCF",
    "88" : "EIGRP",
    "89" : "OSPFIGP",
    "90" : "Sprite-RPC",
    "91" : "LARP",
    "92" : "MTP",
    "93" : "AX.25",
    "94" : "IPIP",
    "95" : "MICP (deprecated)",
    "96" : "SCC-SP",
    "97" : "ETHERIP",
    "98" : "ENCAP",
    "99" : "",
    "100" : "GMTP",
    "101" : "IFMP",
    "102" : "PNNI",
    "103" : "PIM",
    "104" : "ARIS",
    "105" : "SCPS",
    "106" : "QNX",
    "107" : "A/N",
    "108" : "IPComp",
    "109" : "SNP",
    "110" : "Compaq-Peer",
    "111" : "IPX-in-IP",
    "112" : "VRRP",
    "113" : "PGM",
    "114" : "",
    "115" : "L2TP",
    "116" : "DDX",
    "117" : "IATP",
    "118" : "STP",
    "119" : "SRP",
    "120" : "UTI",
    "121" : "SMP",
    "122" : "SM (deprecated)",
    "123" : "PTP",
    "124" : "ISIS over IPv4",
    "125" : "FIRE",
    "126" : "CRTP",
    "127" : "CRUDP",
    "128" : "SSCOPMCE",
    "129" : "IPLT",
    "130" : "SPS",
    "131" : "PIPE",
    "132" : "SCTP",
    "133" : "FC",
    "134" : "RSVP-E2E-IGNORE",
    "135" : "Mobility Header",
    "136" : "UDPLite",
    "137" : "MPLS-in-IP",
    "138" : "manet",
    "139" : "HIP",
    "140" : "Shim6",
    "141" : "WESP",
    "142" : "ROHC",
    "253" : "",
    "254" : "",
    "255" : "Reserved",
}

/* A Simple function to verify error */
func CheckError(err error, msg string) {
    if err  != nil {
        fmt.Println("Error: " , err)
        os.Exit(0)
    } else if msg != "" {
        fmt.Println(msg)
    }
}

func Split(str string) ( string, string , error ) {
    s := strings.Split(str, "=")
    if len(s) < 2 {
        return "" , "", errors.New("Minimum match not found")
    }
    s[1] = strings.Replace(s[1], "\"", "", -1)
    return s[0] , s[1] , nil
}

func TimeCleaner(str string) string {
    //Convert Time Sting "2018-11-22T08:04:22.714+10:00"  into "YYYY-MM-DD HH:MM:ss.SSS"
    s := strings.Split(str, "+")
    result := strings.Replace(s[0], "T", " ", -1)
    return result
}

func main() {
    /* Lets prepare a address at any address at port 8514*/
    ServerAddr,err := net.ResolveUDPAddr("udp",":8514")
    CheckError(err, "")

    /* Now listen at selected port */
    ServerConn, err := net.ListenUDP("udp", ServerAddr)
    CheckError(err, "")
    defer ServerConn.Close()
    buf := make([]byte, 2048)

    // Open up our database connection.
    // The database is called log_data; ; User is logcatcher; password is Jun1perlogs; host is 10.30.0.225
    db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",db_user, db_password, db_address, db_port, db_database))
    CheckError(err, fmt.Sprintf("Connection made to database %s with user %s", db_address, db_user))

    // defer the close till after the main function has finished
    // executing
    defer db.Close()

    stmt, err := db.Prepare (
        `INSERT INTO raw_data (priority, version, time_stamp, hostname, app_name, proc_id, message_id, structured_data, sd_application,
                sd_bytes_from_client, sd_bytes_from_server, sd_connection_tag, sd_destination_address,
                sd_destination_interface_name, sd_destination_port, sd_destination_zone_name, sd_dst_nat_rule_name,
                sd_dst_nat_rule_type, sd_elapsed_time, sd_encrypted, sd_icmp_type, sd_message, sd_name,
                sd_nat_connection_tag, sd_nat_destination_address, sd_nat_destination_port, sd_nat_source_address,
                sd_nat_source_port, sd_nested_application, sd_packet_incoming_interface, sd_packets_from_client,
                sd_packets_from_server, sd_policy_name, sd_profile_name, sd_protocol_id, sd_reason, sd_roles,
                sd_routing_instance, sd_rule_name, sd_service_name, sd_session_id_32, sd_source_address, sd_source_port,
                sd_source_zone_name, sd_src_nat_rule_name, sd_src_nat_rule_type, sd_username)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )`)
    CheckError(err, "")
    defer stmt.Close()

    // <priority>VERSION ISOTIMESTAMP HOSTNAME APPLICATION PID MESSAGEID STRUCTURED-DATA MSG
    //     1        2         3           4        5        -      6        7     8      xxxxxx
    top_syslog_re := regexp.MustCompile(`^<(\d*)>(\d)\s*(\S*)\s*(\S*)\s*(\S*) - (\S*)\s\[(\S*)\s(.*)\]$`)
    fmt.Printf("         Message ID         :     Protocol      :   Scr Address   : Scr Port  :  Dest Address   : Dest Port : Policy Name \n")
    for {
        var row db_row
        n,addr,err := ServerConn.ReadFromUDP(buf)
        // fmt.Println("Received ",string(buf[0:n]), " from ",addr)
        substr := top_syslog_re.FindAllStringSubmatch(string(buf[0:n]), -1)
     		if substr != nil {
            row.syslog_agent = addr
     			  row.priority = substr[0][1]
            row.version = substr[0][2]
            row.time_stamp = TimeCleaner(substr[0][3])
            row.hostname = substr[0][4]
            row.app_name = substr[0][5]
            row.proc_id = "-" // Not Capturing the Process ID field so if it is set we don't capture the row at this point
            row.message_id = substr[0][6]
            row.structured_data = substr[0][8]
            cleaned_SD_DATA := strings.Replace(row.structured_data, "\" ", ";", -1)
            cleaned_SD_DATA = strings.Replace(cleaned_SD_DATA, "\"", "", -1)
            juniper_data_strings := strings.Split(cleaned_SD_DATA,";")

            for _, sd_item := range juniper_data_strings {
                key, value, err := Split(sd_item)
                if err == nil  {
                    switch key {
                      case "application" :
                          row.sd_application = value
                      case "bytes-from-client" :
                          row.sd_bytes_from_client = value
                      case "bytes-from-server" :
                          row.sd_bytes_from_server = value
                      case "connection-tag" :
                          row.sd_connection_tag = value
                      case "destination-address" :
                          row.sd_destination_address = value
                      case "destination-interface-name" :
                          row.sd_destination_interface_name = value
                      case "destination-port" :
                          row.sd_destination_port = value
                      case "destination-zone-name" :
                          row.sd_destination_zone_name = value
                      case "dst-nat-rule-name" :
                          row.sd_dst_nat_rule_name = value
                      case "dst-nat-rule-type" :
                          row.sd_dst_nat_rule_type = value
                      case "elapsed-time" :
                          row.sd_elapsed_time = value
                      case "encrypted" :
                          row.sd_encrypted = value
                      case "icmp-type" :
                          row.sd_icmp_type = value
                      case "message" :
                          row.sd_message = value
                      case "name" :
                          row.sd_name = value
                      case "nat-connection-tag" :
                          row.sd_nat_connection_tag = value
                      case "nat-destination-address" :
                          row.sd_nat_destination_address = value
                      case "nat-destination-port" :
                          row.sd_nat_destination_port = value
                      case "nat-source-address" :
                          row.sd_nat_source_address = value
                      case "nat-source-port" :
                          row.sd_nat_source_port = value
                      case "nested-application" :
                          row.sd_nested_application = value
                      case "packet-incoming-interface" :
                          row.sd_packet_incoming_interface = value
                      case "packets-from-client" :
                          row.sd_packets_from_client = value
                      case "packets-from-server" :
                          row.sd_packets_from_server = value
                      case "policy-name" :
                          row.sd_policy_name = value
                      case "profile-name" :
                          row.sd_profile_name = value
                      case "protocol-id" :
                          row.sd_protocol_id = value
                      case "reason" :
                          row.sd_reason = value
                      case "roles" :
                          row.sd_roles = value
                      case "routing-instance" :
                          row.sd_routing_instance = value
                      case "rule-name" :
                          row.sd_rule_name = value
                      case "service-name" :
                          row.sd_service_name = value
                      case "session-id-32" :
                          row.sd_session_id_32 = value
                      case "source-address" :
                          row.sd_source_address = value
                      case "source-port" :
                          row.sd_source_port = value
                      case "source-zone-name" :
                          row.sd_source_zone_name = value
                      case "src-nat-rule-name" :
                          row.sd_src_nat_rule_name = value
                      case "src-nat-rule-type" :
                          row.sd_src_nat_rule_type = value
                      case "username" :
                          row.sd_username = value
                    }
                }
            }

        }  // end of if substr != nil
        CheckError(err, "")
        // This is where we need to add the row to the mysql // DB:
        // Protocol : Scr Address : Scr Port : Dest Address : Dest Port : Policy Name
        fmt.Printf("%-27s : %-18s : %-15s : %-9s : %-15s : %-9s : %s \n",row.message_id, ProtocolNumbers[row.sd_protocol_id], row.sd_source_address,
            row.sd_source_port, row.sd_destination_address, row.sd_destination_port, row.sd_policy_name)

        //res, err := stmt.Exec()
        _, exec_err := stmt.Exec(row.priority, row.version, row.time_stamp, row.hostname, row.app_name, row.proc_id, row.message_id, row.structured_data,
                      row.sd_application, row.sd_bytes_from_client, row.sd_bytes_from_server, row.sd_connection_tag, row.sd_destination_address,
                      row.sd_destination_interface_name, row.sd_destination_port, row.sd_destination_zone_name, row.sd_dst_nat_rule_name,
                      row.sd_dst_nat_rule_type, row.sd_elapsed_time, row.sd_encrypted, row.sd_icmp_type, row.sd_message, row.sd_name,
                      row.sd_nat_connection_tag, row.sd_nat_destination_address, row.sd_nat_destination_port, row.sd_nat_source_address,
                      row.sd_nat_source_port, row.sd_nested_application, row.sd_packet_incoming_interface, row.sd_packets_from_client,
                      row.sd_packets_from_server, row.sd_policy_name, row.sd_profile_name, row.sd_protocol_id, row.sd_reason, row.sd_roles,
                      row.sd_routing_instance, row.sd_rule_name, row.sd_service_name, row.sd_session_id_32, row.sd_source_address,
                      row.sd_source_port, row.sd_source_zone_name, row.sd_src_nat_rule_name, row.sd_src_nat_rule_type, row.sd_username)
        CheckError(exec_err, "")


    } // end of the contineous for loop.

}
