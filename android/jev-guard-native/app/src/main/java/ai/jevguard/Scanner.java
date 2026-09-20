package ai.jevguard;
import android.content.*;
import android.content.pm.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import org.json.*;
final class Scanner {
 static final long MAX_BYTES=300L*1024*1024;
 static String hex(byte[] a){StringBuilder b=new StringBuilder();for(byte v:a)b.append(String.format(java.util.Locale.ROOT,"%02x",v&255));return b.toString();}
 static String hash(File f)throws Exception{
  MessageDigest d=MessageDigest.getInstance("SHA-256");try(InputStream in=new FileInputStream(f)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1){if(Thread.currentThread().isInterrupted())throw new IOException("Cancelled");d.update(b,0,n);}}return hex(d.digest());
 }
 static JSONObject scan(Context c,File f,String source,boolean splits)throws Exception {
  if(f.length()>MAX_BYTES)throw new IOException("APK exceeds the 300 MB inspection limit.");
  PackageManager pm=c.getPackageManager();
  PackageInfo pi=pm.getPackageArchiveInfo(f.getAbsolutePath(),PackageManager.GET_PERMISSIONS|PackageManager.GET_SIGNING_CERTIFICATES|PackageManager.GET_SERVICES);
  if(pi==null||pi.applicationInfo==null)throw new IOException("Android could not parse this APK. Choose a single .apk file; bundles such as .xapk and .apks are unsupported.");
  ApplicationInfo ai=pi.applicationInfo;ai.sourceDir=f.getAbsolutePath();ai.publicSourceDir=f.getAbsolutePath();
  // Do not load drawable or executable resources from the untrusted APK.
  String label=ai.nonLocalizedLabel==null?pi.packageName:ai.nonLocalizedLabel.toString();
  TreeSet<String> perms=new TreeSet<>();if(pi.requestedPermissions!=null)Collections.addAll(perms,pi.requestedPermissions);
  boolean access=false;if(pi.services!=null)for(ServiceInfo s:pi.services)if("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(s.permission))access=true;
  boolean debug=(ai.flags&ApplicationInfo.FLAG_DEBUGGABLE)!=0;
  JSONArray certificates=new JSONArray();
  if(pi.signingInfo!=null){android.content.pm.Signature[] sigs=pi.signingInfo.getApkContentsSigners();if(sigs!=null)for(android.content.pm.Signature sig:sigs){JSONObject cert=new JSONObject();cert.put("sha256",hex(MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())));try{X509Certificate x=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(sig.toByteArray()));cert.put("subject",x.getSubjectX500Principal().getName());cert.put("expires",x.getNotAfter().toString());}catch(Exception ignored){}certificates.put(cert);}}
  JSONObject r=new JSONObject();r.put("id",UUID.randomUUID().toString());r.put("time",System.currentTimeMillis());r.put("label",label);r.put("package",pi.packageName);r.put("version",pi.versionName==null?"Unknown":pi.versionName);r.put("source",source);r.put("sha256",hash(f));r.put("bytes",f.length());r.put("target_sdk",ai.targetSdkVersion);r.put("permissions",new JSONArray(perms));r.put("accessibility",access);r.put("debuggable",debug);r.put("certificates",certificates);r.put("findings",new JSONArray(RiskRules.assess(perms,access,debug)));r.put("split_base_only",splits);
  r.put("apk_evidence",ApkEvidence.inspect(f));
  return r;
 }
}
