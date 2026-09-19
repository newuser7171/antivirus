package ai.jevguard;
import java.util.*;
/** Evidence rules: declarations indicate capability, not observed behavior or malware. */
public final class RiskRules {
 public static List<String> assess(Set<String> p, boolean accessibility, boolean debug) {
  List<String> r=new ArrayList<>();
  if (p.contains("android.permission.READ_SMS") || p.contains("android.permission.RECEIVE_SMS")) r.add("SMS access requested: could expose private messages or one-time codes if granted.");
  if (p.contains("android.permission.SEND_SMS")) r.add("SMS sending requested: could send chargeable messages if granted.");
  if (p.contains("android.permission.SYSTEM_ALERT_WINDOW")) r.add("Overlay access requested: can draw over other apps if enabled.");
  if (accessibility) r.add("Accessibility service declared: may read or interact with screens if the user enables it.");
  if (p.contains("android.permission.REQUEST_INSTALL_PACKAGES")) r.add("Package installation capability requested: may request installation of other APKs.");
  if (p.contains("android.permission.MANAGE_EXTERNAL_STORAGE")) r.add("Broad file access requested: can access shared files if enabled.");
  if (p.contains("android.permission.RECORD_AUDIO")) r.add("Microphone access requested: can capture audio if granted.");
  if (p.contains("android.permission.ACCESS_BACKGROUND_LOCATION")) r.add("Background location requested: can track location in the background if granted.");
  if (p.contains("android.permission.READ_CONTACTS") && p.contains("android.permission.INTERNET")) r.add("Contacts and internet requested together: review whether this matches the app's purpose.");
  if (accessibility && p.contains("android.permission.SYSTEM_ALERT_WINDOW")) r.add("Combined accessibility and overlay capabilities deserve close review; legitimate assistive apps may need both.");
  if(debug) r.add("Debuggable build: suitable for development; review the source before using it with sensitive data.");
  return r;
 }
 public static String verdict(int malicious,int suspicious) {
  if(malicious<0 || suspicious<0) return "Unknown";
  if(malicious>0) return "Engine detections reported";
  if(suspicious>0) return "Suspicious engine findings";
  return "No engine detections reported";
 }
}
