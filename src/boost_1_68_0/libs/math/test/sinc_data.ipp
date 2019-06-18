#ifndef SC_
#  define SC_(x) static_cast<T>(BOOST_JOIN(x, L))
#endif
   static const boost::array<boost::array<T, 2>, 85> sinc_data = {{
      { SC_(-4.8295154571533203125000000000000000000000e+00), SC_(-2.0564144397615335368562979918981941995753e-01) }, 
      { SC_(-4.6816596984863281250000000000000000000000e+00), SC_(-2.1349862167307660907057655732429291438217e-01) }, 
      { SC_(-4.4761581420898437500000000000000000000000e+00), SC_(-2.1720122073845000360178237918490951754528e-01) }, 
      { SC_(-4.3742771148681640625000000000000000000000e+00), SC_(-2.1566595539683532852848767544650130553932e-01) }, 
      { SC_(-4.1086444854736328125000000000000000000000e+00), SC_(-2.0036183120354498976961729417378586259777e-01) }, 
      { SC_(-3.7394170761108398437500000000000000000000e+00), SC_(-1.5051692429982474112576727957919702319266e-01) }, 
      { SC_(-3.3475914001464843750000000000000000000000e+00), SC_(-6.1102108217798456351460029782718677410135e-02) }, 
      { SC_(-2.6580219268798828125000000000000000000000e+00), SC_(1.7492084497567764117975419002968454997523e-01) }, 
      { SC_(-2.4356470108032226562500000000000000000000e+00), SC_(2.6635787093609254873454189091933075353840e-01) }, 
      { SC_(-2.3019962310791015625000000000000000000000e+00), SC_(3.2336008040116494772234230406698582967077e-01) }, 
      { SC_(-1.7549228668212890625000000000000000000000e-01), SC_(9.9487497449776294957503940828873692843755e-01) }, 
      { SC_(2.5184347547234381013356308010031625599368e-17), SC_(9.9999999999999999999999999999999989429144e-01) }, 
      { SC_(3.1515819566286769684571034133568900870159e-17), SC_(9.9999999999999999999999999999999983445885e-01) }, 
      { SC_(1.0579269457638800205206974780480777553748e-16), SC_(9.9999999999999999999999999999999813465096e-01) }, 
      { SC_(2.0372688216594662252711955829909129533917e-16), SC_(9.9999999999999999999999999999999308255958e-01) }, 
      { SC_(2.5024127294794289849688695426266349386424e-16), SC_(9.9999999999999999999999999999998956321755e-01) }, 
      { SC_(8.7435293617680372862954740753593796398491e-16), SC_(9.9999999999999999999999999999987258449050e-01) }, 
      { SC_(1.6994191427352478562795567995635792613029e-15), SC_(9.9999999999999999999999999999951866242955e-01) }, 
      { SC_(2.1689921858364033524502190175553550943732e-15), SC_(9.9999999999999999999999999999921591214963e-01) }, 
      { SC_(5.7993042470007652444685675163782434538007e-15), SC_(9.9999999999999999999999999999439467837512e-01) }, 
      { SC_(9.2950854532845156308340506257081869989634e-15), SC_(9.9999999999999999999999999998560023106936e-01) }, 
      { SC_(1.5596986863933987033092876117734704166651e-14), SC_(9.9999999999999999999999999995945566679438e-01) }, 
      { SC_(4.3974643804817192815903581504244357347488e-14), SC_(9.9999999999999999999999999967770511703991e-01) }, 
      { SC_(7.2674207146974922899573812173912301659584e-14), SC_(9.9999999999999999999999999911974326925976e-01) }, 
      { SC_(1.3510335428526532020043759985128417611122e-13), SC_(9.9999999999999999999999999695784727681168e-01) }, 
      { SC_(3.5172006366407382316197072213981300592422e-13), SC_(9.9999999999999999999999997938216613602331e-01) }, 
      { SC_(9.0625749092632101877597960992716252803802e-13), SC_(9.9999999999999999999999986311622668998820e-01) }, 
      { SC_(1.7803419329054381847754484624601900577545e-12), SC_(9.9999999999999999999999947173043365642137e-01) }, 
      { SC_(3.6315421156341010089363408042117953300476e-12), SC_(9.9999999999999999999999780198364372929962e-01) }, 
      { SC_(7.1482229857533496897303848527371883392334e-12), SC_(9.9999999999999999999999148381802432457777e-01) }, 
      { SC_(1.4316863666818946398961998056620359420776e-11), SC_(9.9999999999999999999996583790245761992543e-01) }, 
      { SC_(1.6845483341576539260131539776921272277832e-11), SC_(9.9999999999999999999995270494849811121879e-01) }, 
      { SC_(5.0228515791062022799451369792222976684570e-11), SC_(9.9999999999999999999957951603357117216967e-01) }, 
      { SC_(1.1470357996756774809909984469413757324219e-10), SC_(9.9999999999999999999780718145710396513332e-01) }, 
      { SC_(2.3063151388669211883097887039184570312500e-10), SC_(9.9999999999999999999113485080038875672526e-01) }, 
      { SC_(4.5568837592213640164118260145187377929688e-10), SC_(9.9999999999999999996539135067490761622790e-01) }, 
      { SC_(5.1681947610404677106998860836029052734375e-10), SC_(9.9999999999999999995548293818658977143083e-01) }, 
      { SC_(1.3833636458571163529995828866958618164062e-09), SC_(9.9999999999999999968105083722015112831654e-01) }, 
      { SC_(3.3492328910256219387520104646682739257812e-09), SC_(9.9999999999999999813043984027869240754866e-01) }, 
      { SC_(6.7065659692389090196229517459869384765625e-09), SC_(9.9999999999999999250366215004109548978553e-01) }, 
      { SC_(9.6636227908675209619104862213134765625000e-09), SC_(9.9999999999999998443573242597097094310820e-01) }, 
      { SC_(1.7015430842093337560072541236877441406250e-08), SC_(9.9999999999999995174585220965646960507893e-01) }, 
      { SC_(2.9944871471343503799289464950561523437500e-08), SC_(9.9999999999999985055077876078633035382685e-01) }, 
      { SC_(8.4743561501454678364098072052001953125000e-08), SC_(9.9999999999999880308813067486184630883274e-01) }, 
      { SC_(1.3261609410619712434709072113037109375000e-07), SC_(9.9999999999999706882859733604730066894210e-01) }, 
      { SC_(4.5674687498831190168857574462890625000000e-07), SC_(9.9999999999996523038203140225930402260455e-01) }, 
      { SC_(7.8190009844547603279352188110351562500000e-07), SC_(9.9999999999989810537267516226282214649358e-01) }, 
      { SC_(1.7091820154746528714895248413085937500000e-06), SC_(9.9999999999951311613966307169545782039473e-01) }, 
      { SC_(3.5828215914079919457435607910156250000000e-06), SC_(9.9999999999786056490735815715717223661113e-01) }, 
      { SC_(7.4748695624293759465217590332031250000000e-06), SC_(9.9999999999068772083747049385782616904819e-01) }, 
      { SC_(1.1472035112092271447181701660156250000000e-05), SC_(9.9999999997806540173129801546239498657512e-01) }, 
      { SC_(2.5264598662033677101135253906250000000000e-05), SC_(9.9999999989361667574445624564863571981943e-01) }, 
      { SC_(5.4868418374098837375640869140625000000000e-05), SC_(9.9999999949824277759633694228237717097450e-01) }, 
      { SC_(6.3214800320565700531005859375000000000000e-05), SC_(9.9999999933398150353824195889306629656228e-01) }, 
      { SC_(1.6617355868220329284667968750000000000000e-04), SC_(9.9999999539772473883633772577467889886186e-01) }, 
      { SC_(4.5144755858927965164184570312500000000000e-04), SC_(9.9999996603251732010012196212586447596609e-01) }, 
      { SC_(5.9175980277359485626220703125000000000000e-04), SC_(9.9999994163672365877432109245787305708224e-01) }, 
      { SC_(1.8886649049818515777587890625000000000000e-03), SC_(9.9999940549091881399202601506000179969715e-01) }, 
      { SC_(3.2839048653841018676757812500000000000000e-03), SC_(9.9999820266244164525650766832296097320550e-01) }, 
      { SC_(6.5575577318668365478515625000000000000000e-03), SC_(9.9999283308817497693001270399170438932932e-01) }, 
      { SC_(1.0927643626928329467773437500000000000000e-02), SC_(9.9998009788628979560826917234462398401496e-01) }, 
      { SC_(2.7464687824249267578125000000000000000000e-02), SC_(9.9987428656188580073240178797637624570371e-01) }, 
      { SC_(5.4395228624343872070312500000000000000000e-02), SC_(9.9950693280150689842835732266478255630014e-01) }, 
      { SC_(1.0894575715065002441406250000000000000000e-01), SC_(9.9802297731298784088052183750833449909167e-01) }, 
      { SC_(1.8434482812881469726562500000000000000000e-01), SC_(9.9434577998524537639499792018398061310727e-01) }, 
      { SC_(3.4805667400360107421875000000000000000000e-01), SC_(9.7993137091356513777451292422611427589061e-01) }, 
      { SC_(5.6257820129394531250000000000000000000000e-01), SC_(9.4807943690125005126653317657503357778961e-01) }, 
      { SC_(5.6664705276489257812500000000000000000000e-01), SC_(9.4733779787474906002499522123074902162683e-01) }, 
      { SC_(1.5883111953735351562500000000000000000000e+00), SC_(6.2950297241676906424411614772208722050684e-01) }, 
      { SC_(2.7100677490234375000000000000000000000000e+00), SC_(1.5433429787254010454700237187797477463959e-01) }, 
      { SC_(3.5772705078125000000000000000000000000000e+00), SC_(-1.1797403335010845134361979928284854255106e-01) }, 
      { SC_(3.6033649444580078125000000000000000000000e+00), SC_(-1.2364428289578963847004081749648553310113e-01) }, 
      { SC_(3.7766838073730468750000000000000000000000e+00), SC_(-1.5708249021644308711064739246518523759815e-01) }, 
      { SC_(4.0201015472412109375000000000000000000000e+00), SC_(-1.9148470586113360730901280514274812716308e-01) }, 
      { SC_(4.8695030212402343750000000000000000000000e+00), SC_(-2.0283034081254029329390811947499866295346e-01) }, 
      { SC_(4.9605102539062500000000000000000000000000e+00), SC_(-1.9541850863032876003972535140505164063587e-01) }, 
      { SC_(5.4860038757324218750000000000000000000000e+00), SC_(-1.3040266551546396993998529332324853761316e-01) }, 
      { SC_(5.4900817871093750000000000000000000000000e+00), SC_(-1.2978572516839247728729913746105155167508e-01) }, 
      { SC_(5.5786609649658203125000000000000000000000e+00), SC_(-1.1609801955039980348827321624165824542852e-01) }, 
      { SC_(5.6123390197753906250000000000000000000000e+00), SC_(-1.1076470982849211097675159261300665760170e-01) }, 
      { SC_(5.6264133453369140625000000000000000000000e+00), SC_(-1.0851736256355344896484050447605119909590e-01) }, 
      { SC_(5.6471138000488281250000000000000000000000e+00), SC_(-1.0519352624476319628955249191079616784999e-01) }, 
      { SC_(5.7733154296875000000000000000000000000000e+00), SC_(-8.4537850909120915738253194859770692286972e-02) }, 
      { SC_(5.9145755767822265625000000000000000000000e+00), SC_(-6.0920499174038826963883262039519566066855e-02) }, 
      { SC_(5.9575347900390625000000000000000000000000e+00), SC_(-5.3700933786881587614051406850527216765734e-02) }
   }};
//#undef SC_

