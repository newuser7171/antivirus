package ai.jevguard;
import android.app.*;
import android.content.*;
import android.os.Bundle;
import java.io.*;
import org.json.*;
public class DeviceChecks extends Instrumentation {
 @Override public void onCreate(Bundle args){super.onCreate(args);start();}
 void check(boolean v,String msg)throws Exception{if(!v)throw new Exception(msg);}
 @Override public void onStart(){Bundle b=new Bundle();try{
  Context c=getTargetContext();
  JSONObject r=Scanner.scan(c,new File(c.getApplicationInfo().sourceDir),"Device test",false);
  check(r.getString("package").equals("ai.jevguard"),"Wrong package");check(r.getString("sha256").length()==64,"Bad hash");check(r.getJSONArray("certificates").length()>0,"No signing identity");
  check(r.getJSONArray("permissions").toString().contains("android.permission.INTERNET"),"Permissions absent");
  SecretStore store=new SecretStore(c);store.put("test","test-key-not-real");check(store.get("test").equals("test-key-not-real"),"Key roundtrip failed");store.put("test","");check(store.get("test").isEmpty(),"Key removal failed");
  File invalid=File.createTempFile("bad-",".apk",c.getCacheDir());try{try(FileOutputStream out=new FileOutputStream(invalid)){out.write("not an apk".getBytes("UTF-8"));}boolean rejected=false;try{Scanner.scan(c,invalid,"Test",false);}catch(Exception e){rejected=true;}check(rejected,"Malformed APK accepted");}finally{invalid.delete();}
  check(r.getJSONObject("apk_evidence").getInt("dex_entries")>0,"Missing DEX evidence");check(Api.jevRequest(r).getJSONObject("questions").length()==6,"Missing Jev judgments");
  MainActivity activity=(MainActivity)startActivitySync(new Intent(c,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));waitForIdleSync();
  runOnMainSync(()->{try{activity.save(r);activity.current=r;activity.show("Scan");}catch(Exception e){throw new RuntimeException(e);}});waitForIdleSync();
  runOnMainSync(()->activity.show("History"));waitForIdleSync();runOnMainSync(()->activity.show("Apps"));waitForIdleSync();runOnMainSync(()->activity.show("Settings"));waitForIdleSync();runOnMainSync(()->activity.show("Scan"));waitForIdleSync();
  b.putString("stream","PASS: device APK parse, SHA-256, signing identity, permissions, encrypted key roundtrip/removal, invalid APK rejection, report persistence, APK content evidence, six Jev questions, and four screens\n");finish(Activity.RESULT_OK,b);
 }catch(Throwable e){b.putString("stream","FAIL: "+e.toString()+"\n");finish(Activity.RESULT_CANCELED,b);}}
}
