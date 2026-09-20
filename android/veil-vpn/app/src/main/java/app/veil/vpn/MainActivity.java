package app.veil.vpn;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.*;

public final class MainActivity extends Activity {
    private final int BG=Color.rgb(11,18,26), CARD=Color.rgb(22,33,45), MINT=Color.rgb(152,232,208), MUTED=Color.rgb(164,181,197);
    private TunnelController controller;
    private LinearLayout page;
    private TextView state,traffic;
    private Button connect;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private final Runnable refresh=new Runnable(){public void run(){if(state!=null){state.setText(controller.status);state.setTextColor(controller.verified()?MINT:Color.WHITE);traffic.setText(String.format(Locale.US,"↓ %.1f KB    ↑ %.1f KB",controller.rx/1024.0,controller.tx/1024.0));connect.setText(controller.up?"Disconnect":"Connect VPN");connect.setEnabled(!controller.busy);}handler.postDelayed(this,1000);}};
    @Override public void onCreate(Bundle b){super.onCreate(b);getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);controller=TunnelController.get(this);home();}
    @Override public void onResume(){super.onResume();handler.post(refresh);}
    @Override public void onPause(){handler.removeCallbacks(refresh);super.onPause();}
    @Override public void onDestroy(){io.shutdownNow();super.onDestroy();}
    private int dp(int n){return (int)(n*getResources().getDisplayMetrics().density);}
    private void screen(String subtitle){
        state=null;traffic=null;connect=null;
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.setBackgroundColor(BG);
        page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);page.setPadding(dp(22),dp(22),dp(22),dp(28));scroll.addView(page);
        scroll.setOnApplyWindowInsetsListener((v,insets)->{android.graphics.Insets i=insets.getInsets(WindowInsets.Type.systemBars());v.setPadding(i.left,i.top,i.right,i.bottom);return insets;});
        setContentView(scroll);scroll.requestApplyInsets();
        text(page,"V E I L",30,Color.WHITE,true);text(page,"POWERED BY JEV",11,MINT,true);text(page,subtitle,16,MUTED,false);
        LinearLayout nav=new LinearLayout(this);page.addView(nav);
        navButton(nav,"Home",this::home);navButton(nav,"Jev",this::jev);navButton(nav,"Settings",this::settings);
    }
    private void navButton(LinearLayout row,String label,Runnable action){Button b=new Button(this);b.setText(label);b.setTextSize(12);b.setAllCaps(false);row.addView(b,new LinearLayout.LayoutParams(0,dp(50),1));b.setOnClickListener(v->action.run());}
    private LinearLayout card(String title){LinearLayout c=new LinearLayout(this);c.setOrientation(LinearLayout.VERTICAL);c.setPadding(dp(18),dp(18),dp(18),dp(18));GradientDrawable g=new GradientDrawable();g.setColor(CARD);g.setCornerRadius(dp(20));c.setBackground(g);LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.topMargin=dp(18);page.addView(c,p);text(c,title,20,Color.WHITE,true);return c;}
    private TextView text(LinearLayout parent,String value,int size,int color,boolean bold){TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(color);t.setPadding(0,dp(7),0,dp(7));t.setLineSpacing(dp(3),1);if(bold)t.setTypeface(null,Typeface.BOLD);parent.addView(t);return t;}
    private Button button(LinearLayout parent,String label,Runnable action){Button b=new Button(this);b.setText(label);b.setAllCaps(false);b.setMinHeight(dp(48));parent.addView(b,new LinearLayout.LayoutParams(-1,-2));b.setOnClickListener(v->action.run());return b;}
    private void message(String msg){if(!isDestroyed())new AlertDialog.Builder(this).setMessage(msg).setPositiveButton("OK",null).show();}
    private void home(){
        screen("Your connection. Your choice.");
        LinearLayout c=card("Connection");state=text(c,controller.status,22,Color.WHITE,true);traffic=text(c,"",14,MUTED,false);
        connect=button(c,controller.up?"Disconnect":"Connect VPN",()->{if(controller.up)controller.disconnect();else connectPrompt();});
        text(c,"A recent handshake confirms contact with your VPN server. It does not prove that every website is reachable.",13,MUTED,false);
        LinearLayout f=card(controller.mode().title);text(f,controller.mode().description,15,MUTED,false);button(f,"Describe your preference to Jev",this::jev);
        LinearLayout p=card("Bring your VPN");text(p,"Import a WireGuard .conf from your VPN provider or your own server. Veil does not include VPN servers.",15,MUTED,false);
        button(p,"Import WireGuard file",()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"),20));
        button(p,"Paste configuration",this::pasteProfile);
        text(page,"DNS filtering cannot remove every ad or ads served from the same domain as content. Apps using their own DNS and Android Private DNS can bypass it.",13,MUTED,false);
    }
    private void connectPrompt(){
        try{ProfilePolicy.apply(ProfilePolicy.parse(controller.secrets.get("profile")),controller.mode());}
        catch(Exception e){message(e.getMessage());return;}
        new AlertDialog.Builder(this).setTitle("Connect Veil VPN?")
            .setMessage("This replaces any other active VPN. Traffic will use your configured WireGuard server. DNS mode: "+controller.mode().title+". "+controller.mode().description+"\n\nNo profile, keys or browsing traffic is sent to Jev.")
            .setNegativeButton("Cancel",null).setPositiveButton("Continue",(d,w)->{Intent consent=VpnService.prepare(this);if(consent!=null)startActivityForResult(consent,21);else startVpn();}).show();
    }
    private void startVpn(){
        try{startForegroundService(new Intent(this,ShieldVpnService.class));if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},22);}
        catch(Exception e){message("Could not start VPN. Check Android VPN settings.");}
    }
    private void pasteProfile(){
        EditText input=new EditText(this);input.setHint("[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\n…");input.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);input.setMinLines(6);input.setAutofillHints((String[])null);input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Private WireGuard configuration").setView(input).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();
        dialog.setOnShowListener(d->dialog.getButton(-1).setOnClickListener(v->{try{controller.saveProfile(input.getText().toString());input.setText("");dialog.dismiss();message("Profile saved securely on this device.");}catch(Exception e){message(e.getMessage());}}));dialog.show();
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request==21){if(result==RESULT_OK)startVpn();else message("VPN permission was not granted.");}
        if(request==20&&result==RESULT_OK&&data!=null&&data.getData()!=null){
            android.net.Uri uri=data.getData();
            io.execute(()->{try(InputStream in=getContentResolver().openInputStream(uri)){
                if(in==null)throw new IOException();ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buf=new byte[4096];int n;
                while((n=in.read(buf))!=-1){if(out.size()+n>65536)throw new IOException("Profile exceeds 64 KB.");out.write(buf,0,n);}
                controller.saveProfile(out.toString(StandardCharsets.UTF_8.name()));runOnUiThread(()->message("Profile imported securely on this device."));
            }catch(Exception e){runOnUiThread(()->message("Could not import this profile. Check that it is a full-tunnel WireGuard configuration and disconnect before importing."));}});
        }
    }
    private void jev(){
        screen("Tell Jev how you want to browse.");
        LinearLayout c=card("Choose filtering with Jev");
        text(c,"Try: “Block ads and trackers” or “Use family filtering for my child’s device.”",15,MUTED,false);
        EditText preference=new EditText(this);preference.setHint("What would you like to filter?");preference.setTextColor(Color.WHITE);preference.setHintTextColor(MUTED);preference.setMinLines(3);preference.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE);preference.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(2000)});c.addView(preference);
        text(c,"Ask Jev sends only this text to TypeSafe using your API key. Do not include private information. Your account’s API charges may apply. Recommendations never change settings automatically.",13,MUTED,false);
        Button ask=button(c,"Ask Jev",()->{});
        TextView result=text(c,"A TypeSafe API key is needed for Jev. Manual filtering works without one.",14,MUTED,false);
        Button apply=button(c,"Apply recommendation",()->{});apply.setVisibility(View.GONE);
        ask.setOnClickListener(v->{
            String request=preference.getText().toString().trim();if(request.isEmpty()){preference.setError("Describe a preference");return;}
            ask.setEnabled(false);apply.setVisibility(View.GONE);result.setText("Jev is evaluating your preference…");
            io.execute(()->{try{
                JevApi.Recommendation r=JevApi.ask(request,controller.secrets.get("jev"));
                runOnUiThread(()->{if(isDestroyed())return;ask.setEnabled(true);
                    if(!r.applicable()){result.setText("Jev could not confidently match this request to a supported mode. Choose manually or describe it more simply. Model confidence: "+Math.round(r.confidence*100)+"%.");return;}
                    FilterMode m=FilterMode.from(r.choice);result.setText("Jev recommends: "+m.title+"\n"+m.description+"\nModel confidence: "+Math.round(r.confidence*100)+"%. This is not a safety score.");
                    apply.setVisibility(View.VISIBLE);apply.setOnClickListener(w->new AlertDialog.Builder(this).setTitle("Apply "+m.title+"?").setMessage(m.description+" Disconnect first. This changes DNS for your next VPN connection.").setNegativeButton("Cancel",null).setPositiveButton("Apply",(d,z)->setMode(m)).show());
                });
            }catch(Exception e){runOnUiThread(()->{if(isDestroyed())return;ask.setEnabled(true);result.setText(e instanceof JevApi.HttpError?e.getMessage():"Jev is unavailable or returned an invalid answer. Check your key and network. Manual filtering remains available.");});}});
        });
        button(c,"Add / replace TypeSafe API key",this::keyDialog);
        LinearLayout manual=card("Choose manually");for(FilterMode m:FilterMode.values())button(manual,m.title,()->new AlertDialog.Builder(this).setTitle(m.title).setMessage(m.description).setNegativeButton("Cancel",null).setPositiveButton("Apply",(d,w)->setMode(m)).show());
    }
    private void setMode(FilterMode m){try{controller.setMode(m);message("Filtering set to "+m.title+". Connect the VPN to use it.");}catch(Exception e){message(e.getMessage());}}
    private void keyDialog(){
        EditText key=new EditText(this);key.setHint("TypeSafe API key");key.setSingleLine(true);key.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);key.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        new AlertDialog.Builder(this).setTitle("Your TypeSafe API key").setMessage("Stored encrypted with Android Keystore. Get a personal key at console.typesafe.ai. Never paste VPN keys here.").setView(key).setNegativeButton("Cancel",null).setPositiveButton("Save",(d,w)->{try{String value=key.getText().toString().trim();if(value.isEmpty()||value.contains("\n")||value.contains("\r"))throw new Exception();controller.secrets.put("jev",value);key.setText("");message("Jev key saved.");}catch(Exception e){message("Could not save the key. Enter a valid non-empty key.");}}).show();
    }
    private void settings(){
        screen("Privacy, without the guesswork.");
        LinearLayout c=card("Connection safeguards");text(c,"For protection when the VPN stops, enable Always-on VPN and Block connections without VPN in Android settings. Veil itself does not enforce a kill switch. IPv6 is tunneled when the profile includes ::/0; otherwise it is blocked while this VPN is active.",15,MUTED,false);
        button(c,"Open Android VPN settings",()->{try{startActivity(new Intent("android.settings.VPN_SETTINGS"));}catch(Exception e){message("Open Settings and search for VPN.");}});
        LinearLayout p=card("Your data");text(p,"VPN traffic goes to the server in your profile. In a filtering mode, DNS queries go to AdGuard through that tunnel. Only requests you submit with Ask Jev go to TypeSafe. Veil keeps no browsing history or analytics and does not inspect page contents.",15,MUTED,false);
        button(p,"Remove Jev API key",()->confirm("Remove Jev key?",()->{try{controller.secrets.put("jev","");message("Jev key removed.");}catch(Exception e){message("Could not remove key.");}}));
        button(p,"Remove VPN profile",()->confirm("Remove VPN profile?",()->{try{controller.clearProfile();message("Profile removed.");}catch(Exception e){message(e.getMessage());}}));
        text(page,"Veil 0.2.0 · Personal preview\nWireGuard tunnel library: Apache-2.0; wireguard-go: MIT; Go runtime: BSD-3-Clause. TypeSafe Jev is a separate online service. Not affiliated with WireGuard, AdGuard or TypeSafe.",12,MUTED,false);
    }
    private void confirm(String title,Runnable action){new AlertDialog.Builder(this).setTitle(title).setNegativeButton("Cancel",null).setPositiveButton("Remove",(d,w)->action.run()).show();}
}
