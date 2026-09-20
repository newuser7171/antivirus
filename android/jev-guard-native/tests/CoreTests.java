package ai.jevguard;
import java.io.*;import java.util.*;import java.util.zip.*;import org.json.*;
public class CoreTests {
 static int n=0;static void ok(boolean b,String m){n++;if(!b)throw new AssertionError(m);}interface Throws{void run()throws Exception;}static void rejects(Throws t)throws Exception{boolean b=false;try{t.run();}catch(Exception e){b=true;}ok(b,"Expected rejection");}
 static JSONObject response(String choice,double confidence,double severity)throws Exception {
 JSONObject ps=new JSONObject();for(String k:new String[]{"clean","suspicious_pua","malicious","insufficient_evidence"})ps.put(k,k.equals(choice)?1:0);
 JSONObject sp=new JSONObject();for(int i=0;i<5;i++)sp.put(""+i,i==(int)severity?1:0);
 JSONObject a=new JSONObject().put("verdict",new JSONObject().put("type","choice").put("choice",choice).put("confidence",confidence).put("probabilities",ps)).put("threat_severity",new JSONObject().put("type","score").put("score",severity).put("confidence",0.8).put("probabilities",sp));
 for(String k:new String[]{"is_packed_or_obfuscated","has_c2_download","has_persistence","has_injection_or_evasion"})a.put(k,new JSONObject().put("type","noul").put("noul",0.2));return new JSONObject().put("model","test-fixture").put("answers",a);
 }
 public static void main(String[] args)throws Exception {
 ok(RiskRules.assess(Collections.emptySet(),false,false).isEmpty(),"No fabricated flags");
 ok(RiskRules.verdict(1,0).equals("Engine detections reported"),"Engine detections preserved");
 rejects(()->Api.jevRequest(new JSONObject()));
 JSONObject r=new JSONObject().put("package","example").put("keys","secret").put("apk_evidence",new JSONObject().put("partial",true));JSONObject p=Api.jevRequest(r);
 ok(p.getJSONObject("questions").length()==6,"All desktop judgment types ported");ok(!p.getJSONObject("state").has("keys"),"No keys in state");ok(p.getJSONObject("state").getJSONObject("apk_evidence").getBoolean("partial"),"Coverage retained");
 ok(Api.parseJev(response("malicious",0.9,3)).getString("action").equals("AVOID_INSTALLATION"),"Malicious recommendation");
 ok(Api.parseJev(response("clean",0.9,0)).getString("action").equals("NO_AI_THREAT_IDENTIFIED"),"Benign is not certified safe");
 ok(Api.parseJev(response("clean",0.4,0)).getString("action").equals("MANUAL_REVIEW"),"Uncertain benign requires review");
 ok(Api.parseJev(response("insufficient_evidence",1,0)).getString("action").equals("MANUAL_REVIEW"),"Unknown never allowed");
 JSONObject bad=response("malicious",0.9,3);bad.getJSONObject("answers").remove("has_persistence");rejects(()->Api.parseJev(bad));
 rejects(()->Api.parseJev(response("malicious",2,3)));
 JSONObject inconsistent=response("malicious",0.9,3);inconsistent.getJSONObject("answers").getJSONObject("threat_severity").put("score",0);rejects(()->Api.parseJev(inconsistent));
 JSONObject type=response("malicious",0.9,3);type.getJSONObject("answers").getJSONObject("has_c2_download").put("noul","0.9");rejects(()->Api.parseJev(type));
 JSONObject wrong=response("malicious",0.9,3);wrong.getJSONObject("answers").getJSONObject("verdict").put("choice","clean");rejects(()->Api.parseJev(wrong));
 File f=File.createTempFile("fixture-",".apk");try{
 try(ZipOutputStream z=new ZipOutputStream(new FileOutputStream(f))){z.putNextEntry(new ZipEntry("classes.dex"));z.write("DexClassLoader\u0000sendTextMessage\u0000https://example.com/path?secret=private\u0000".getBytes("UTF-8"));z.closeEntry();z.putNextEntry(new ZipEntry("assets/large.bin"));z.write(new byte[ApkEvidence.ENTRY_LIMIT+32]);z.closeEntry();}
 JSONObject e=ApkEvidence.inspect(f);ok(e.getInt("dex_entries")==1,"DEX counted");ok(e.getBoolean("partial"),"Bounded scan disclosed");ok(e.getJSONArray("code_string_references").toString().contains("dynamic_code_loading"),"Code reference extracted");ok(e.getJSONArray("embedded_domain_samples").toString().contains("example.com"),"Domain extracted");ok(!e.toString().contains("secret=private"),"URL paths and query omitted");ok(e.getInt("sampled_bytes")<=ApkEvidence.TOTAL_LIMIT,"Read budget enforced");
 }finally{f.delete();}
 ok(ApkEvidence.entropy(new byte[100])==0,"Uniform entropy");byte[] all=new byte[256];for(int i=0;i<256;i++)all[i]=(byte)i;ok(ApkEvidence.entropy(all)==8,"Entropy range");
 System.out.println("PASS: "+n+" core checks");
 }
}
