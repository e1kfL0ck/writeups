Challenge Mobile Hackvens

Peremièrement, on décompile le fichier avec JADX-gui. On ouvre le fichier  `Sources>com>example.hackvens>MainActivity`.

```Java
package com.example.hackvens;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.example.hackvens.databinding.ActivityMainBinding;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;

    public native String checkFlag(String str);

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        final TextView textView = this.binding.sampleText;
        this.binding.button.setOnClickListener(new View.OnClickListener() { // from class: com.example.hackvens.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                textView.setText(MainActivity.this.checkFlag(MainActivity.this.binding.editTextTextPassword.getText().toString()));
            }
        });
    }

    static {
        System.loadLibrary("lib-hackvens");
    }
}
```

Une fonction attire particulièrement notre regard `checkFlag()`. Mais impossible de trouver le code associé. Toutefois, il y a l'ajout d'une lib externe `System.loadLibrary("lib-hackvens")`.

On peut la retouver dans `Ressources>lib` compilée selon les besoins. Analysons la avec Ghidra.

Après avoir localisé la fonction d'intérêt, on trouve ce bout de code :

```C
  if (uVar5 == 0x15) {
                    /* try { // try from 00120f33 to 00120f7e has its CatchHandler @ 001211a8 */
    iVar1 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,0,9,"HACKVENS{");
    if (iVar1 == 0) {
                    /* try { // try from 00120fd3 to 0012100c has its CatchHandler @ 00121154 */
      iVar1 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,0x14,1,"}");
      if (iVar1 == 0) {
                    /* try { // try from 00121012 to 0012111c has its CatchHandler @ 00121156 */
        iVar1 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,10,1,"3");
        iVar2 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,0xc,1,"3");
        iVar3 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,0xf,1,"3");
        if ((((iVar2 + iVar1 + iVar3 == 0) &&
             (iVar1 = std::__ndk1::basic_string<>::compare
                                ((basic_string<> *)&local_50,0x10,4,"_JN1"), iVar1 == 0)) &&
            (iVar1 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,0xd,2,"rs"),
            iVar1 == 0)) &&
           ((iVar1 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,9,1,"R"),
            iVar1 == 0 &&
            (iVar1 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,0xb,1,"v"),
            iVar1 == 0)))) {
          uVar6 = (**(code **)(*param_1 + 0x538))(param_1,&local_7f);
        }
        else {
          if ((local_68 & 1) != 0) {
            pcVar4 = (char *)CONCAT62(uStack_56,CONCAT11(local_67[0x10],local_67[0xf]));
          }
          uVar6 = (**(code **)(*param_1 + 0x538))(param_1,pcVar4);
        }
      }
      else {
        if ((local_68 & 1) != 0) {
          pcVar4 = (char *)CONCAT62(uStack_56,CONCAT11(local_67[0x10],local_67[0xf]));
        }
        uVar6 = (**(code **)(*param_1 + 0x538))(param_1,pcVar4);
      }
    }
    else {
      if ((local_68 & 1) != 0) {
        pcVar4 = (char *)CONCAT62(uStack_56,CONCAT11(local_67[0x10],local_67[0xf]));
      }
      uVar6 = (**(code **)(*param_1 + 0x538))(param_1,pcVar4);
    }
  }
```

Il semblerait que le flag soit contenu à l'intérieur. Ce n'est plus qu'une question de reverse tout ca.

On remarque immédiatemment `iVar1 = std::__ndk1::basic_string<>::compare((basic_string<> *)&local_50,0,9,"HACKVENS{");`. Cette instruction effectue une comparaison entre `HACKVENS{` et les `9` caractères à partir de `0`. Juste après, il y a `}` qui se trouve en position `0x14` soit 20ème. Il nous faut donc trouver les 11 caractères manquants en appliquant la même méthode. Les caractères aux indices `10`, `12`, et `15` doivent être tous égaux à `3`. Les caractères aux indices 0x10 doivent être `_JN1`. Les caractères aux indices `13` et `14` doivent être `rs`. Le caractère à l'index `9` doit être `R`. Le caractère à l'index `0xb` (`11`) doit être `v`.

En assembleant tout on obtient : `HACKVENS{3rs_Rv_JN1}`. Et l'on peut valider le challenge !
