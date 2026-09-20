package app.veil.vpn;

enum FilterMode {
    ADS("ads", "Ads & trackers", "AdGuard DNS blocks known advertising and tracking domains.", new String[]{"94.140.14.14", "94.140.15.15"}),
    FAMILY("family", "Family filtering", "AdGuard DNS adds adult-content filtering and supported Safe Search enforcement.", new String[]{"94.140.14.15", "94.140.15.16"}),
    PROFILE("profile", "Profile DNS", "Use the DNS in your WireGuard profile. Veil adds no filtering.", new String[]{});
    final String id, title, description;
    final String[] dns;
    FilterMode(String id, String title, String description, String[] dns) { this.id=id; this.title=title; this.description=description; this.dns=dns; }
    static FilterMode from(String id) { for (FilterMode m: values()) if(m.id.equals(id)) return m; throw new IllegalArgumentException("Unknown filtering mode"); }
}
