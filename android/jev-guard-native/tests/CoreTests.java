package ai.jevguard;
import java.util.*;
import org.json.*;
public class CoreTests {
 static int n=0;
 static void ok(boolean b,String message){n++;if(!b)throw new AssertionError(message);}
 interface Throws{void run()throws Exception;}
 static void rejects(Throws f)throws Exception{boolean rejected=false;try{f.run();}catch(Exception e){rejected=true;}ok(rejected,"Malformed response must be rejected");}
 public static void main(String[] args)throws Exception{
  ok(RiskRules.assess(Collections.emptySet(),false,false).isEmpty(),"No fabricated capability flags");
  Set<String> p=new HashSet<>(Arrays.asList("android.permission.INTERNET","android.permission.READ_CONTACTS"));
  ok(RiskRules.assess(p,false,false).size()==1,"Combined capability evidence");
  ok(!RiskRules.verdict(-1,0).contains("No engine"),"Unknown is not clean");
  ok(RiskRules.verdict(1,0).equals("Engine detections reported"),"Malicious result visible");
  ok(RiskRules.verdict(0,1).equals("Suspicious engine findings"),"Suspicious not clean");
  ok(RiskRules.verdict(0,0).equals("No engine detections reported"),"Zero detections is not safe verdict");
  JSONObject report=new JSONObject().put("package","test.example").put("permissions",new JSONArray()).put("sha256","secret hash").put("keys","private").put("label","filename").put("certificates","identity");
  JSONObject request=Api.jevRequest(report),state=request.getJSONObject("state");
  ok(!state.has("keys")&&!state.has("sha256")&&!state.has("label")&&!state.has("certificates"),"Cloud evidence minimization");
  ok(request.getString("model").equals("jev-latest"),"Model configured");
  ok(request.getJSONObject("questions").getJSONObject("review_priority").getJSONObject("criteria").has("insufficient_evidence"),"Unknown branch available");
  JSONObject choice=new JSONObject("{\"type\":\"choice\",\"choice\":\"review\",\"confidence\":0.7,\"probabilities\":{\"review\":0.8,\"limited_signals\":0.1,\"insufficient_evidence\":0.1}}");
  JSONObject raw=new JSONObject().put("answers",new JSONObject().put("review_priority",choice));
  ok(Api.parseJev(raw).getString("choice").equals("review"),"Jev response parsed");
  choice.put("choice","safe");rejects(()->Api.parseJev(raw));choice.put("choice","review");choice.put("confidence",2);rejects(()->Api.parseJev(raw));choice.put("confidence",0.7);choice.getJSONObject("probabilities").put("review",0.1);rejects(()->Api.parseJev(raw));
  JSONObject stats=new JSONObject().put("malicious",2).put("suspicious",1);
  JSONObject vt=new JSONObject().put("data",new JSONObject().put("attributes",new JSONObject().put("last_analysis_stats",stats)));
  ok(Api.parseVT(vt).getInt("malicious")==2,"VT counts preserved");stats.remove("malicious");rejects(()->Api.parseVT(vt));rejects(()->Api.parseVT(new JSONObject()));
  System.out.println("PASS: "+n+" core checks");
 }
}
