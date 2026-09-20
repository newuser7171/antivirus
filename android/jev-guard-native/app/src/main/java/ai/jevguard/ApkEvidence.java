package ai.jevguard;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.util.regex.*;
import org.json.*;

/** Bounded, non-executing APK content inspection. Strings are references, not observed behavior. */
final class ApkEvidence {
 static final int ENTRY_LIMIT=2*1024*1024, TOTAL_LIMIT=16*1024*1024, FILE_LIMIT=256;
 static final String[][] SIGNALS={
  {"dynamic_code_loading","DexClassLoader","InMemoryDexClassLoader","loadDex"},
  {"shell_execution","Ljava/lang/Runtime;","Ljava/lang/ProcessBuilder;","/system/bin/sh","su -c"},
  {"sms_access","Landroid/telephony/SmsManager;","sendTextMessage","content://sms"},
  {"accessibility_control","performGlobalAction","dispatchGesture","getRootInActiveWindow"},
  {"overlay_windows","TYPE_APPLICATION_OVERLAY","SYSTEM_ALERT_WINDOW"},
  {"device_admin","DeviceAdminReceiver","lockNow","wipeData"},
  {"boot_persistence","BOOT_COMPLETED","RECEIVE_BOOT_COMPLETED"},
  {"install_packages","REQUEST_INSTALL_PACKAGES","PackageInstaller","ACTION_INSTALL_PACKAGE"},
  {"debugger_checks","isDebuggerConnected","TracerPid","/proc/self/status"},
  {"credential_targets","Login Data","wallet.dat","/data/data/com.android.chrome"},
  {"crypto_apis","Ljavax/crypto/Cipher;","SecretKeySpec","AES/CBC","AES/GCM"},
  {"network_apis","HttpURLConnection","Lokhttp3/","Ljava/net/Socket;","WebSocket"}
 };
 static byte[] readBounded(InputStream in,int limit)throws IOException {
  ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int n;
  while(out.size()<limit&&(n=in.read(b,0,Math.min(b.length,limit-out.size())))!=-1){if(Thread.currentThread().isInterrupted())throw new IOException("Cancelled");out.write(b,0,n);}return out.toByteArray();
 }
 static double entropy(byte[] b){if(b.length==0)return 0;int[] counts=new int[256];for(byte v:b)counts[v&255]++;double e=0;for(int n:counts)if(n>0){double p=(double)n/b.length;e-=p*Math.log(p)/Math.log(2);}return Math.round(e*1000)/1000.0;}
 static JSONObject inspect(File file)throws Exception {
  JSONObject out=new JSONObject();JSONArray files=new JSONArray(),signals=new JSONArray(),domains=new JSONArray();Set<String> hosts=new TreeSet<>();int bytes=0,visited=0,inspected=0,dex=0,nativeFiles=0,payloads=0;boolean partial=false;
  Pattern url=Pattern.compile("https?://([A-Za-z0-9.-]{1,253})(?=[:/\\s\\x00]|$)");
  try(ZipFile zip=new ZipFile(file)){
   Enumeration<? extends ZipEntry> entries=zip.entries();
   while(entries.hasMoreElements()){
    ZipEntry e=entries.nextElement();if(++visited>10000){partial=true;break;}if(e.isDirectory())continue;
    String name=e.getName(),lower=name.toLowerCase(Locale.ROOT);if(lower.endsWith(".dex"))dex++;if(lower.endsWith(".so"))nativeFiles++;if(lower.endsWith(".apk")||lower.endsWith(".jar")||lower.endsWith(".sh"))payloads++;
    boolean relevant=lower.endsWith(".dex")||lower.endsWith(".so")||lower.startsWith("assets/")||lower.endsWith(".js")||lower.endsWith(".sh");
    if(!relevant)continue;if(inspected>=FILE_LIMIT||bytes>=TOTAL_LIMIT){partial=true;continue;}
    int limit=Math.min(ENTRY_LIMIT,TOTAL_LIMIT-bytes);byte[] data;
    try(InputStream in=zip.getInputStream(e)){data=readBounded(in,limit);if(in.read()!=-1)partial=true;}
    inspected++;bytes+=data.length;String s=new String(data,java.nio.charset.StandardCharsets.ISO_8859_1);
    JSONArray matched=new JSONArray();
    for(String[] group:SIGNALS){JSONArray terms=new JSONArray();for(int i=1;i<group.length;i++)if(s.contains(group[i]))terms.put(group[i]);if(terms.length()>0)matched.put(new JSONObject().put("kind",group[0]).put("references",terms));}
    if(matched.length()>0&&signals.length()<64)signals.put(new JSONObject().put("entry",name.substring(0,Math.min(name.length(),180))).put("matches",matched));else if(matched.length()>0)partial=true;
    Matcher m=url.matcher(s);while(m.find()&&hosts.size()<40)hosts.add(m.group(1).toLowerCase(Locale.ROOT));
    if(files.length()<24)files.put(new JSONObject().put("entry",name.substring(0,Math.min(name.length(),180))).put("sample_bytes",data.length).put("sample_entropy",entropy(data)));
   }
  }catch(ZipException e){throw new IOException("APK content archive could not be inspected.");}
  for(String host:hosts)domains.put(host);
  return out.put("schema",1).put("dex_entries",dex).put("native_entries",nativeFiles).put("nested_payload_entries",payloads).put("entries_inspected",inspected).put("sampled_bytes",bytes).put("partial",partial)
   .put("entry_samples",files).put("code_string_references",signals).put("embedded_domain_samples",domains)
   .put("limitations","Bounded byte/string inspection, not DEX call-graph analysis or execution. References may be unused library code. Entropy may reflect normal compression. Domain samples omit URL paths and queries. Counts are partial if archive enumeration stops; samples are not exhaustive. No signatures or behavior have been validated.");
 }
}
