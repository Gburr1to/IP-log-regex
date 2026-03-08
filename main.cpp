#include <iostream>
#include <fstream>
#include <regex>
#include <unordered_map>
#include <vector>
#include <string>

using namespace std;

/**
 * @brief **Funkcija iterira skozi vrstice filea.**
 * * Z regex preveri, če vrstica vsebuje Connection from.
 * Če ga, iz iste vrstice z drugim regexom potegnem ven IP. IP dodam v mapo.
 * Če IP že obstaja, se bo njegova vrednost (števec) samo povečala.
 * * @param reg_ip Regularni izraz za validacijo IP naslova.
 * @param file Vhodni tok datoteke z logi.
 * @return **unordered_map<string,int>** Mapa z IP naslovi in številom ponovitev.
 */
unordered_map<string,int> list_matches(const regex& reg_ip, ifstream& file) {
    unordered_map<string,int> matches;
    string line;
    regex reg_connection(R"(Connection from)");

    while (std::getline(file, line)) {
        smatch line_match;
        if (regex_search(line, line_match, reg_connection)) {
            if (regex_search(line, line_match, reg_ip)) {
                matches[line_match.str()]++;
            }
        }
    }
    return matches;
}

/**
 * @brief Izpiše vse najdene IP naslove in njihove števce.
 * @param matches Mapa IP naslovov.
 */
void print_matches(const unordered_map<string, int>& matches) {
    cout << "--- IP adresses ---" << "\n";
    for (const auto& [ip, count] : matches) {
        cout << ip << " (" << count << "x)\n";
    }
    cout << "\n";
}

/**
 * @brief **Funkcija Iterira skozi vrstice, išče failed ali invalid user.**
 * * V tisti vrstici regex_search datum in username.
 * **CAPTURE GROUP** - (skupino v oklepajih). Pri smatch je na indeksu 0 shranjen celoten ujem (npr. "for admin"),
 * na indeksu 1 pa dejansko to, kar nas zanima ("admin"). Zato **user[1]**.
 * Oboje shranim v vektor parov.
 * * @param file Vhodni tok datoteke.
 * @return **vector<pair<string,string>>** Vektor parov (uporabnik, datum).
 */
vector<pair<string,string>> list_hackers(ifstream& file) {
    vector<pair<string,string>> matches;
    string line;

    regex reg_failed(R"(Failed|Invalid user)");
    regex reg_date(R"(^\w+\s+\d+)");
    regex reg_user(R"((?:for|user)\s+([^\s]+))");

    while (std::getline(file, line)) {
        smatch line_match, date, user;
        if (regex_search(line, line_match, reg_failed)) {
            string found_user = "Neznano";
            string found_date = "Neznano";

            if (regex_search(line, user, reg_user)) {
                found_user = user[1].str(); // skupina 1
            }
            if (regex_search(line, date, reg_date)) {
                found_date = date.str();
            }
            matches.emplace_back(found_user, found_date);
        }
    }
    return matches;
}

/**
 * @brief Izpiše seznam potencialnih napadalcev.
 * @param list Vektor parov z uporabniki in datumi.
 */
void print_hackers(const vector<pair<string,string>>& list) {
    cout << "--- Hackers ---" << "\n";
    for (const auto& [user, date] : list) {
        cout << date << ": " << user << "\n";
    }
    cout << "\n";
}

/**
 * @brief **Funkcija loči IP naslov po pikah (isto ujemanje, po grupah).**
 * * **AND** med referenčnim IP in masko. Ta rezultat (4 deli) si shranim v vektor **and_result**.
 * Iterira skozi vse najdene IP-je iz mape in vsakega spet loči po pikah.
 * Za vsak IP naredi AND z masko. Če se vsi 4 deli ujemajo z **and_result**, IP shranim v subnets.
 * Maska in referenčni IP imata 4 dele. Z regexom (\\d+)\\.(\\d+)... ju razbijemo na posamezne dele.
 * **Smatch[0] shrani celoten IP string! Zato berem Smatch[1].**
 * * @param initial_ip Referenčni IP naslov.
 * @param mask Omrežna maska.
 * @param ip_list Seznam vseh zaznanih IP naslovov.
 * @return **vector<string>** Seznam IP naslovov, ki pripadajo isti podmreži.
 */
vector<string> find_subadresses(const string& initial_ip, const string& mask, const unordered_map<string, int>& ip_list) {
    vector<string> subnets;
    regex reg_ip_parts(R"((\d+)\.(\d+)\.(\d+)\.(\d+))");

    smatch match_mask, match_initial_ip;
    regex_search(mask, match_mask, reg_ip_parts);
    regex_search(initial_ip, match_initial_ip, reg_ip_parts);


    vector<int> and_result(4);
    for (int i = 0; i < 4; i++) {
        and_result[i] = stoi(match_initial_ip[i+1].str()) & stoi(match_mask[i+1].str());
    }

    for (const auto& [ip, repetitions] : ip_list) {
        smatch match_current_ip;
        if (regex_search(ip, match_current_ip, reg_ip_parts)) {
            bool matches_subnet = true;
            for (int i = 0; i < 4; i++) {
                if ((stoi(match_current_ip[i+1].str()) & stoi(match_mask[i+1].str())) != and_result[i]) {
                    matches_subnet = false;
                    break;
                }
            }
            if (matches_subnet) {
                subnets.push_back(ip);
            }
        }
    }
    return subnets;
}

/**
 * @brief Izpiše IP naslove, ki so bili uvrščeni v podmrežo.
 * @param subnets Vektor ustreznih IP naslovov.
 */
void print_subadresses(const vector<string>& subnets) {
    cout << "--- IP subadresses ---" << "\n";
    for (const auto& net : subnets) {
        cout << net << "\n";
    }
}

/**
 * @brief Glavni vhodni program.
 * * Skrbi za validacijo argumentov, preverjanje pravilnosti IP formata
 * in zaporedno klicanje analiznih funkcij.
 */
int main(int argc, char* argv[]) {
    if (argc < 4) {
        cerr << "Uporaba: " << argv[0] << " <ime_datoteke> <IP_naslov> <maska>" << endl;
        return 1;
    }

    string file_name = argv[1];
    string ip = argv[2];
    string mask = argv[3];

    regex reg_ip(R"(\b((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\b)");

    if (!regex_match(ip, reg_ip)) {
        cerr << "Napaka: IP naslov ni veljaven!" << endl;
        return 1;
    }

    if (!regex_match(mask, reg_ip)) {
        cerr << "Napaka: Maska ni veljavna!" << endl;
        return 1;
    }

    ifstream file(file_name);

    if (!file.is_open()) {
        cerr << "Napaka pri odpiranju datoteke!" << endl;
        return 1;
    }

    auto ip_list = list_matches(reg_ip, file);
    print_matches(ip_list);

    file.clear();
    file.seekg(0);

    auto hackers = list_hackers(file);
    print_hackers(hackers);
    auto subadresses = find_subadresses(ip, mask, ip_list);
    print_subadresses(subadresses);

    file.close();
    return 0;
}