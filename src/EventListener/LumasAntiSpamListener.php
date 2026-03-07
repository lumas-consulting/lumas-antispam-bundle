<?php

declare(strict_types=1);

namespace Lumas\AntispamBundle\EventListener;

use Contao\CoreBundle\DependencyInjection\Attribute\AsHook;
use Contao\Form;
use Contao\PageModel;
use Contao\Widget;
use Doctrine\DBAL\Connection;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

final class LumasAntiSpamListener
{
	// Cache TTL for isBlockedGlobal() cache
	private const STATUS_TTL_SEC = 300;

	// IP block threshold (active when block_count >= 5)
	private const GLOBAL_BLOCK_THRESHOLD = 5;

	// Session: 2 Fehlversuche erlaubt => Block ab 3. Fehlversuch
	private const SESSION_INVALID_THRESHOLD = 2;

	/**
	 * Request-scope state per formKey:
	 * - true  => this submit is spam/blocked (add errors to all fields)
	 * - false => passed
	 * - null  => undecided
	 *
	 * @var array<string, bool|null>
	 */
	private array $processedForms = [];

	private array $stopwords = [
		'de' => [
			'aber','alle','allem','allen','aller','alles','als','also','am','an','ander','andere','anderem','anderen','anderer','anderes','anderm','andern','anderr','anders','auch','auf','aus','bei','bin','bis','bist','da','damit','dann','das','dass','daß','dein','deine','deinem','deinen','deiner','deines','dem','den','denn','der','des','dessen','deshalb','die','dies','diese','diesem','diesen','dieser','dieses','doch','dort','du','durch','ein','eine','einem','einen','einer','eines','einmal','er','es','etwas','euer','eure','eurem','euren','eurer','eures','für','gegen','gewesen','habe','haben','hat','hatte','hatten','hier','hin','hinter','ich','ihm','ihn','ihr','ihre','ihrem','ihren','ihrer','ihres','im','in','indem','ins','ist','ja','jede','jedem','jeden','jeder','jedes','jene','jenem','jenen','jener','jenes','jetzt','kann','kein','keine','keinem','keinen','keiner','keines','können','könnte','machen','man','manche','manchem','manchen','mancher','manches','mein','meine','meinem','meinen','meiner','meines','mich','mir','mit','muss','musste','nach','nicht','nichts','noch','nun','nur','ob','oder','ohne','sehr','sein','seine','seinem','seinen','seiner','seines','selbst','sich','sie','sind','so','solche','solchem','solchen','solcher','solches','soll','sollen','sollte','sondern','sonst','um','und','uns','unse','unser','unsere','unserem','unseren','unserer','unseres','unter','viel','vom','von','vor','war','waren','warst','was','weg','weil','weiter','welche','welchem','welchen','welcher','welches','wenn','wer','werde','werden','wie','wieder','wir','wird','wirst','wo','wollen','wollte','während','würde','würden','zu','zum','zur','zwar','zwischen','ab','allein','alles','andere','bald','beide','beim','beispiel','bekannt','besonders','besser','besten','bin','bis','bisschen','bitte','dabei','dadurch','dafür','dagegen','daher','damals','danach','darauf','daraus','darin','darum','darüber','davon','dazu','dennoch','derselbe','deshalb','desselben','dessen','dich','dir','drei','drin','dritte','drunter','drüber','dunkel','durch','durfte','durften','eben','ebenso','eigene','eigenen','eigner','einfach','einig','einige','einigen','einiger','einiges','einmal','eins','einzig','ende','endlich','entlang','entweder','erst','erste','ersten','erster','erstes','etwa','euch','euer','eurer','fast','fertig','fort','fragte','frei','freie','freier','freies','ganz','ganze','ganzen','ganzer','ganzes','gar','gebe','geben','geblieben','gebracht','gedacht','gefallen','gegangen','gehalten','gekommen','gemacht','genommen','gesagt','gesehen','gespielt','gestern','getan','getreten','gewesen','geworden','gibt','ging','glück','groß','große','großen','großer','großes','gut','gute','guten','guter','gutes','hallo','halt','hast','hat','hatte','hattest','hatten','hattet','heißt','helfen','heute','hier','hin','hinein','hinten','hinter','hoch','höher','höre','hören','immer','irgend','irgendwas','irgendwen','irgendwie','irgendwo','ist','ja','jahr','jahre','jahren','je','jede','jedem','jeden','jeder','jedes','jemand','jemanden','jener','jenes','jetzt','jung','junge','jungen','junger','junges','kam','kann','kannst','kaum','kein','keine','keinem','keinen','keiner','keines','kennt','klar','klein','kleine','kleinen','kleiner','kleines','kommen','kommt','konnte','konntest','konnten','konntet','kurz','können','könnt','könnte','könnten','küche','lassen','lasse','lässt','laufen','laut','leben','leicht','leise','lernen','lesen','letzte','letzten','letzter','letztes','leute','liebe','liegen','lieber','links','lustig','machen','macht','machte','machten','mag','mags','mal','man','manche','manchem','manchen','mancher','manches','mann','mehr','mein','meine','meinem','meinen','meiner','meines','mensch','menschen','mich','mir','mit','muss','musst','musste','mussten','mut','mutter','müssen','müsst','müsste','nach','nachdem','nacher','nacht','nah','nahe','name','natürlich','neben','nein','nennen','neu','neue','neuen','neuer','neues','neun','nicht','nichts','nie','niemand','noch','nun','nur','nächste','oben','obgleich','obschon','obwohl','oder','oft','ohne','ordnung','paar','passiert','platz','plötzlich','punkt','quasi','recht','rechten','rechter','rechtes','richtig','rund','ruft','sache','sagen','sagt','sagte','sagten','sah','samt','satz','schauen','scheinen','schlecht','schnell','schon','schreiben','schreien','schritt','schuh','schwarz','schwer','schwester','sechs','sehen','sehr','sei','seien','sein','seine','seinem','seinen','seiner','seines','seit','seite','selber','selbst','setzen','sich','sicher','sie','sieben','siehst','sieht','sind','sitzen','so','sobald','sofort','sogar','soll','sollst','sollte','sollten','somit','sondern','sonst','soviel','soweit','sowie','später','statt','stehen','steht','stelle','stellen','stets','stück','stunde','suche','suchen','tag','tage','tagen','teil','tief','tisch','tot','trotzdem','tun','tust','tut','uhr','um','unbedingt','und','uns','unse','unser','unsere','unserem','unseren','unserer','unseres','unten','unter','vater','vergangen','vermag','verschieden','versteht','versuchen','viel','viele','vielen','vieles','vielleicht','vier','vom','von','vor','vorbei','vorher','vorne','wahr','war','waren','warst','wart','warum','was','wasser','weder','weg','wegen','weil','weiß','weit','weiter','weitere','weitgehend','welche','welchem','welchen','welcher','welches','welt','wem','wen','wenig','wenige','wenigstens','wenn','wer','werde','werden','werdet','weshalb','wessen','wie','wieder','wieso','will','willst','wir','wird','wirklich','wirst','wo','woher','wohin','wohl','wollen','wollt','wollte','wollten','wolltest','wort','wurde','wurden','während','wäre','wären','würde','würden','zehn','zeit','ziemlich','zu','zuerst','zugleich','zum','zunächst','zur','zurück','zusammen','zwei','zwischen','zwölf'
		],
		'en' => [
			'a','about','above','after','again','against','all','am','an','and','any','are','as','at','be','because','been','before','being','below','between','both','but','by','can','could','did','do','does','doing','down','during','each','few','for','from','further','had','has','have','having','he','her','here','hers','herself','him','himself','his','how','i','if','in','into','is','it','its','itself','just','me','more','most','my','myself','no','nor','not','now','of','off','on','once','only','or','other','ought','our','ours','ourselves','out','over','own','same','she','should','so','some','such','than','that','the','their','theirs','them','themselves','then','there','these','they','this','those','through','to','too','under','until','up','very','was','we','were','what','when','where','which','while','who','whom','why','with','would','you','your','yours','yourself','yourselves','actually','already','also','anyway','couldnt','didnt','doesnt','dont','every','everyone','everything','isnt','maybe','please','really','something','thanks','wasnt','without','across','almost','alone','along','another','anyone','anything','anywhere','became','become','becomes','becoming','beside','besides','beyond','cannot','certain','certainly','clear','clearly','come','could','down','empty','enough','even','ever','every','everybody','everyone','everything','everywhere','except','fifth','first','five','former','formerly','forty','found','four','from','front','full','further','get','give','go','had','has','have','hence','her','here','hers','herself','him','himself','his','how','however','hundred','i','if','in','inc','indeed','interest','into','is','it','its','itself','keep','last','latter','latterly','least','less','ltd','made','many','may','me','meanwhile','might','mill','mine','more','moreover','most','mostly','move','much','must','my','myself','name','namely','neither','never','nevertheless','next','nine','no','nobody','none','noone','nor','not','nothing','now','nowhere','of','off','often','on','once','one','only','onto','or','other','others','otherwise','our','ours','ourselves','out','over','own','part','per','perhaps','please','put','rather','re','same','see','seem','seemed','seeming','seems','serious','several','she','should','show','side','since','sincere','six','sixty','so','some','somehow','someone','something','sometime','sometimes','somewhere','still','such','system','take','ten','than','that','the','their','them','themselves','then','thence','there','thereafter','thereby','therefore','therein','thereupon','these','they','thick','thin','third','this','those','though','three','through','throughout','thru','thus','to','together','too','top','toward','towards','twelve','twenty','two','un','under','until','up','upon','us','very','via','was','we','well','were','what','whatever','when','whence','whenever','where','whereafter','whereas','whereby','wherein','whereupon','wherever','whether','which','while','whither','who','whoever','whole','whom','whose','why','will','with','within','without','would','yet','you','your','yours','yourself','yourselves'
		],
		'fr' => [
			'alors','au','aucuns','aussi','autre','avant','avec','avoir','bon','car','ce','cela','ces','ceux','chaque','ci','comme','comment','dans','des','du','dedans','dehors','depuis','deux','doit','donc','dos','droite','début','elle','elles','en','encore','essai','est','et','eu','fait','faites','fois','font','hors','ici','il','ils','je','juste','la','le','les','leur','là','ma','maintenant','mais','mes','mine','moins','mon','mot','même','ne','ni','nommés','notre','nous','ou','où','par','parce','pas','peut','peu','plupart','pour','pourquoi','quand','que','quel','quelle','quelles','quels','qui','sa','sans','ses','seulement','si','sien','son','sont','sous','soyez','sur','ta','tandis','tellement','tels','tes','ton','tous','tout','trop','très','tu','voient','vont','votre','vous','vu','ça','étaient','état','étiez','été','être','assez','beaucoup','combien','était','étaient','faisait','faisaient','afin','ailleurs','ainsi','allaient','allô','allons','après','assez','attendu','auprès','auquel','aura','auraient','aurait','auront','aussi','autour','autre','autrefois','autrement','autres','autrui','aux','auxquelles','auxquels','avaient','avais','avait','avant','avec','avez','aviez','avions','avons','ayant','ayez','ayons','bah','bas','base','beau','beaucoup','bien','bigre','bon','boum','bravo','brrr','c’est','c’était','car','ce','ceci','cela','celle','celle-là','celle-ci','celles','celles-là','celles-ci','celui','celui-là','celui-ci','cent','cependant','certain','certaine','certaines','certains','certes','ces','cet','cette','ceux','ceux-là','ceux-ci','chacun','chacune','chaque','cher','chercher','chère','chères','chers','chez','chut','cinq','cinquantaine','cinquante','cinquantième','cinquième','clac','clic','combien','comme','comment','comparable','comparere','compris','concernant','contre','couic','crac','d’un','d’une','dans','davantage','de','debout','dedans','dehors','delà','demain','depuis','derrière','des','desquelles','desquels','dessous','dessus','deux','deuxième','deuxièmement','devant','devers','devra','différent','différente','différentes','différents','dire','directement','disent','dit','dite','dits','dix','dix-huit','dix-neuf','dix-sept','dixième','doit','doivent','donc','dont','douze','douzième','dring','du','duquel','durant','dès','désormais','effet','egale','egalement','egales','eh','elle','elle-même','elles','elles-mêmes','en','encore','enfin','entre','envers','environ','es','ès','est','et','etant','etc','etre','eu','euh','eux','eux-mêmes','excepté','face','façon','fais','faisaient','faisant','fait','faites','fasse','février','fi','flac','floc','font','font-ils','fût','fûtes','grâce','guère','hé','hem','heu','hormis','hors','hélas','hui','huit','huitième','hum','hurrah','i','ici','il','ils','importe','j’ai','j’avais','j’étais','jamais','je','jusqu’au','jusqu’à','jusque','juste','k','l’','l’un','l’une','la','laquelle','le','lequel','les','lesquelles','lesquels','leur','leurs','lez','lors','lorsque','lui','lui-meme','lui-même','là','là-bas','là-haut','m’','ma','maint','maintenant','mais','malgré','me','même','mêmes','merci','mes','mien','mienne','miennes','miens','mille','mince','mine','moi','moi-meme','moi-même','moins','mon','moyennant','multiple','multiples','même','mêmes','n’','na','naturel','naturelle','naturelles','ne','néanmoins','neuf','neuvième','ni','nombreux','non','nos','notre','nous','nous-mêmes','nôtre','nôtres','nulle','o','obstant','oh','ohé','olé','ollé','on','ont','onze','onzième','ore','ou','où','ouf','ouias','oust','ouste','outre','ouvert','p’tite','paf','pan','par','parce','parfois','parlent','parler','parmi','parsemé','partant','particulier','particulière','particulièrement','pas','passé','pendant','pense','permet','personne','peu','peut','peuvent','peux','pff','pfft','pfut','pif','pif-paf','pis','pitié','piz','plupart','plus','plusieurs','plutôt','pouah','pour','pourquoi','premier','première','premièrement','près','proche','psitt','pu','puis','puisque','pur','pure','q','qu’','qu’elle','qu’elles','qu’il','qu’ils','qu’on','quand','quant','quante','quantième','quatorze','quatre','quatre-vingt','quatrième','quatrièmement','que','quel','quelconque','quelle','quelles','quelque','quelques','quelqu’un','quels','qui','quiconque','quinze','quoi','quoique','r','rare','rarement','rares','relative','relativement','remarquable','rend','rendre','restant','reste','restent','restrictif','revoilà','rien','s’','sa','sacrebleu','sait','sans','sapristi','sauf','se','sein','seize','selon','semblable','semblaient','semble','semblent','sent','sept','septième','sera','seraient','serait','seront','ses','seul','seule','seulement','si','sien','sienne','siennes','siens','sinon','six','sixième','soi','soi-même','soit','soixante','son','sont','sous','souvent','soyez','soyons','spectacle','suis','suite','sujet','sur','surtout','t’','ta','tac','tant','tardive','te','tel','telle','tellement','telles','tels','tenant','tenez','tenir','tente','tes','tic','tien','tienne','tiennes','tiens','toc','toi','toi-même','ton','touchant','toujours','tous','tout','toute','toutefois','toutes','treize','trente','très','trois','troisième','troisièmement','trop','très','t’','tu','u','un','une','unes','uns','v’là','vif','vifs','vingt','vivat','vive','vives','vlan','voici','voilà','vont','vos','votre','vous','vous-mêmes','vôtre','vôtres','vrai','vraiment','vrais','y','z','zut','à','â','ça','ès','étaient','étais','était','étant','étiez','étions','été','étée','étées','étés','etes','être','ô'
		],
		'es' => [
			'al','ante','antes','año','años','aquel','aquellas','aquellos','aqui','arriba','atras','aun','aunque','bajo','bien','cabe','cada','casi','cierto','como','con','conseguimos','conseguir','consigo','consigue','consiguen','consigues','cual','cuando','dentro','desde','donde','dos','el','el','ellas','ellos','empleais','emplean','emplear','empleas','empleo','en','encima','entonces','entre','era','eramos','eran','eras','eres','es','esa','esas','ese','esos','esta','estaba','estado','estais','estamos','estan','estar','este','esto','estos','estoy','fue','fueron','fui','fuimos','ha','hace','hacer','haces','hago','han','hasta','incluso','intenta','intentais','intentamos','intentan','intentar','intentas','intento','ir','la','largo','las','lo','los','mientras','mio','modo','muchos','muy','nos','nosotros','otro','para','pero','podeis','podemos','poder','podria','por','porque','puedo','quien','sabe','sabemos','saben','saber','sabes','ser','si','siendo','sin','sobre','sois','somos','son','soy','su','sus','tal','tambien','tras','tuyo','un','una','unas','uno','unos','usted','ustedes','va','van','vaya','vive','vives','vivir','yo','ademas','algun','alguna','algunas','alguno','algunos','ambos','bueno','creo','esta','estamos','estoy','habia','habian','hasta','mismo','mucho','nuestra','nuestro','puede','pueden','siempre','tambien','tanto','tenemos','tener','tengo','tiempo','todo','todos','a','actualmente','acuerdo','adelante','ademas','ademas','afirmar','agregó','ahi','ahora','algun','alguna','algunas','alguno','algunos','alrededor','alrededor','anterior','antes','apenas','aproximadamente','aquel','aquella','aquellas','aquello','aquellos','aqui','aseguró','así','asimismo','atras','aun','aunque','ayer','bajo','bien','buen','buena','buenas','bueno','buenos','cada','casi','cerca','cierta','ciertas','cierto','ciertos','cinco','comento','como','con','conmigo','conocer','conseguichen','considera','consideró','consigo','consigue','consiguen','consigues','contó','contra','cosas','creo','cual','cuales','cualquier','cuando','cuanto','cuatro','cuenta','da','dado','dan','dar','de','debe','deben','debido','decir','dejó','del','demas','dentro','desde','despues','detras','dice','dicen','dicho','dieron','diferente','diferentes','diez','dio','donde','dos','durante','e','ejemplo','el','ella','ellas','ello','ellos','embargo','emplean','emplear','empleas','empleo','en','encima','encuentra','entonces','entre','era','eramos','eran','eras','eres','es','esa','esas','ese','eso','esos','esta','estaba','estaban','estado','estais','estamos','estan','estando','estar','estará','este','esto','estos','estoy','estuvo','ex','existe','existen','explicó','expresó','fin','fue','fuera','fueron','fui','fuimos','gran','grandes','gueno','ha','haber','habia','habian','habra','hace','hacen','hacer','haces','hago','han','hasta','hay','haya','he','hecho','hemos','hicieron','hizo','hoy','hubo','igual','incluso','indicó','informó','intenta','intentais','intentamos','intentan','intentar','intentas','intento','ir','junto','la','lado','las','le','leer','les','llegó','lo','los','luego','lugar','manera','manifestó','mas','mayor','me','mediante','mejor','mencionó','menos','mi','mientras','mio','misma','mismas','mismo','mismos','modo','momento','mucha','muchas','mucho','muchos','muy','nada','nadie','ni','ningun','ninguna','ningunas','ninguno','ningunos','no','nos','nosotras','nosotros','nuestra','nuestras','nuestro','nuestros','nueva','nuevas','nuevo','nuevos','nunca','o','ocho','otra','otras','otro','otros','para','parece','parte','partir','pasada','pasado','pese','poca','pocas','poco','pocos','podeis','podemos','poder','podria','podriamos','podrian','podrias','poner','por','porque','posible','primer','primera','primero','primeros','principalmente','propia','propias','propio','propios','proximo','proximos','pudo','pueda','puede','pueden','pues','que','qué','quedo','queremos','quien','quienes','quiere','quiere','realizado','realizar','realizó','respecto','sabe','sabeis','sabemos','saben','saber','sabes','se','sea','sean','segun','segunda','segundo','seis','ser','será','serán','seria','señaló','si','sido','siempre','siendo','siete','sigue','siguiente','sin','sino','sobre','sois','sola','solamente','solas','solo','solos','somos','son','soy','su','sus','tal','tambien','tambien','tan','tanto','tendrá','tendrán','teneis','tenemos','tener','tenga','tengo','tenia','tenian','tercera','tiene','tienen','toda','todas','todavia','todo','todos','total','trabaja','trabajan','trabajar','trabajas','trabajo','tras','trata','través','tres','tuvo','un','una','unas','uno','unos','usted','ustedes','va','valla','vamos','van','varias','varios','vaya','veces','ver','vez','vi','viejo','vieja','viejos','viejas','vieron','vino','vivir','vivo','yo'
		],
		'it' => [
			'a','ad','al','alla','alle','altri','anche','aveva','avevano','avete','avevo','bene','che','chi','ci','coi','col','come','con','contro','cui','da','dagli','dai','dal','dall','dalla','dalle','degli','dei','del','dell','della','delle','di','dov','dove','e','ebbe','ebbero','ed','era','erano','eravamo','eravate','eri','ero','faccia','facciamo','facciano','faccio','facciate','fai','fanno','faranno','fare','farebbe','farebbero','farei','faremmo','faremo','fareste','faresti','farete','faresti','fatto','fece','fecero','fui','fummo','furono','foste','fosti','gli','ha','hanno','ho','i','il','in','io','la','le','lei','li','lo','loro','lui','ma','mi','mia','mie','miei','mio','ne','negl','nei','nel','nell','nella','nelle','no','noi','non','nostra','nostre','nostri','nostro','o','per','perché','più','può','qualche','quella','quelle','quelli','quello','questa','queste','questi','questo','sa','saranno','sarà','se','sei','si','sia','siamo','siano','siate','siete','sono','sta','stanno','stata','state','stati','stato','su','sua','sue','sugli','sui','sul','sull','sulla','sulle','suo','suoi','tra','tu','tua','tue','tuoi','tuo','un','una','uno','vi','voi','vostra','vostre','vostri','vostro','abbiamo','abbia','avevamo','avevate','hanno','stiamo','stanno','tutto','tutti','abbastanza','accanto','agli','ahimè','ai','al','alcuna','alcune','alcuni','alcuno','all','alla','alle','allo','allora','altre','altri','altrimenti','altro','altrove','altrui','anche','ancora','anzi','appena','appunto','aveva','avevamo','avevano','avevate','avevi','avevo','avrà','avrai','avranno','avrebbe','avrebbero','avrei','avremmo','avremo','avreste','avresti','avrete','avrà','avrò','avuta','avute','avuti','avuto','basta','ben','bene','benissimo','berrei','berremmo','berremo','berreste','berresti','berrete','berrà','berrai','berranno','berrebbe','berrebbero','bevete','beveva','bevevamo','bevevano','bevevate','bevevi','bevevo','buon','buona','buone','buoni','c','che','chi','chicchessia','chiunque','ci','ciò','cioè','circa','clic','coi','col','colei','coll','colla','colle','collo','coloro','colui','come','cominci','compresa','comprese','compresi','compreso','con','concernente','conclusione','consecutivo','considerato','contro','cortesia','così','cui','d','da','dagli','dai','dal','dall','dalla','dalle','dallo','dappertutto','davanti','degl','degli','dei','del','dell','della','delle','dello','dentro','detto','deve','devono','di','diem','dietro','dinanzi','dire','diretto','dirimpetto','diventa','diventare','diventato','dopo','dove','dovunque','due','e','ebbe','ebbero','ebbi','ecc','ecco','ed','egli','ella','eppure','era','erano','eravamo','eravate','eri','ero','essendo','esser','essere','essi','essa','esse','esso','faccia','facciamo','facciano','faccio','facciate','fai','fanno','faranno','fare','farebbe','farebbero','farei','faremmo','faremo','fareste','faresti','farete','farà','farò','fatto','favore','fece','fecero','feci','fin','finalmente','finché','fino','forse','foste','fosti','fra','fui','fummo','furono','già','gli','gliela','gliele','glieli','glielo','gliene','grazie','ha','hai','hanno','ho','i','ieri','il','improvvisamente','in','infatti','inoltre','insieme','intorno','invece','io','l','la','le','lei','lessi','letta','lette','letti','letto','li','lo','lontano','loro','lui','lungo','ma','macché','magari','mai','malgrado','me','medesimo','mediante','meglio','meno','mentre','messi','messo','mi','mia','mie','miei','milioni','minimi','mio','moltissimo','molto','multa','ne','negl','negli','nei','nel','nell','nella','nelle','nello','nemmeno','neppure','nessun','nessuna','nessune','nessuni','nessuno','neanche','niente','no','noi','nome','non','nonché','nonostante','nostra','nostre','nostri','nostro','notte','nulla','nuovo','o','od','oggi','ogni','ognuna','ognuno','oltre','oppure','ora','ore','ossia','ovunque','ovvero','per','perché','perciò','perfino','però','persone','piuttosto','più','poco','poteva','potevano','potrebbe','potrebbero','presto','proprio','può','pure','purtroppo','quaggiù','qualche','qualcosa','qualcuno','quale','quali','qualunque','quando','quante','quanti','quanto','quanti','quasiché','quasi','quassù','quella','quelle','quelli','quello','questa','queste','questi','questo','qui','quindi','quotidiano','recente','recentemente','rendere','rossi','sa','saranno','sarà','sarai','saran','saranno','sarei','saremmo','saremo','sareste','saresti','sarete','sarà','sarò','scopo','scorso','se','secondo','seguente','seguito','sei','sembra','sembrare','sembrato','sempre','senza','sette','si','sia','siamo','siano','siate','siete','sono','sta','stai','stanno','stare','stata','state','stati','stato','stavolta','stesso','su','subito','successivo','sue','sugli','sui','sul','sull','sulla','sulle','sullo','suo','suoi','talvolta','tanto','te','tempi','tengo','terzo','ti','titolo','tra','tranne','tre','trenta','triplo','troppo','trovato','tu','tua','tue','tuo','tuoi','tutta','tutte','tutti','tutto','u','un','una','uno','uomini','v','va','vai','valle','vanno','vanti','varia','varie','vari','vario','ve','vedrai','venerdì','venne','vennero','venni','venti','vi','via','vicino','visto','vita','voi','vostra','vostre','vostri','vostro','è'
		]
	];
	
	/**
	 * Defaults; can be overridden by form or root page fields (lumas_antispam_*)
	 */
	private array $defaults = [
		'minDelay'      => 15,
		'minLen'        => 15,
		'stopwordCount' => 2,
		'language'      => 'de',
		'ip_block_ttl'  => 24, // base hours (kept for compatibility / admin UI)
		'ip_block'      => 0,  // enforcement toggle
		'blockTime'     => 30, // minutes (session block time)
	];

	public function __construct(
		private readonly LoggerInterface $logger,
		private readonly RequestStack $requestStack,
		private readonly Connection $db,
		private readonly CacheInterface $cache,
	) {
	}

	/* =========================================================
	 * Helpers
	 * =======================================================*/

	private function isOne(mixed $v): bool
	{
		return (string) ($v ?? '0') === '1';
	}

	private function normalizeIp(?string $ip): ?string
	{
		$ip = $ip ? trim($ip) : null;

		return ($ip !== null && $ip !== '') ? $ip : null;
	}

	/**
	 * Key for the CacheInterface layer (status cache).
	 * Must be stable and PSR-compatible.
	 */
	private function cacheKeyForIp(string $ip): string
	{
		return 'lumas_antispam_status_' . preg_replace('/[^A-Za-z0-9_]/', '_', $ip);
	}

	/**
	 * ONE consistent key for session state + timestamps.
	 * In Contao, $formId is usually auto_form_XX and matches FORM_SUBMIT.
	 */
	private function getFormKey(Request $request, string $formId): string
	{
		return (string) ($request->request->get('FORM_SUBMIT') ?: $formId);
	}

	/** Nice alias for logging */
	private function getFormAliasForLogging(Form $form, string $formId): string
	{
		return (string) ($form->formID ?: $formId);
	}

	private function extractEmail(array $formData, Request $request): ?string
	{
		foreach (['email', 'e-mail', 'mail', 'email_address'] as $k) {
			$v = $formData[$k] ?? $request->request->get($k);
			$v = is_string($v) ? trim($v) : null;

			if ($v !== null && $v !== '') {
				return $v;
			}
		}

		return null;
	}

	private function getSetting(string $key, Form $form): mixed
	{
		$dcaKey = 'lumas_antispam_' . $key;

		// 1) per-form
		if (($val = $form->{$dcaKey} ?? null) !== null && (string) $val !== '') {
			return $val;
		}

		// 2) root page
		$request = $this->requestStack->getCurrentRequest();
		$page = $request?->attributes->get('pageModel') ?? ($GLOBALS['objPage'] ?? null);

		if ($page instanceof PageModel) {
			$rootId = (int) ($page->rootId ?: $page->id);
			$root = PageModel::findByPk($rootId);

			if ($root instanceof PageModel) {
				if (($val = $root->{$dcaKey} ?? null) !== null && (string) $val !== '') {
					return $val;
				}
			}
		}

		return $this->defaults[$key] ?? null;
	}

	/**
	 * Marker: stable per POST-request, different across separate POSTs.
	 * Used to avoid double-counting if validateFormField runs multiple times.
	 */
	private function makeSubmitMarker(string $formKey, SessionInterface $session, Request $request): string
	{
		$t = (string) ($request->server->get('REQUEST_TIME') ?? time());

		return hash('sha256', $formKey . '|' . $session->getId() . '|' . $t);
	}

	private function logOnly(string $ip, string $reason, string $formAlias, array $details = []): void
	{
		try {
			$this->db->insert('tl_lumas_antispam_log', [
				'tstamp'     => time(),
				'ip_address' => $ip,
				'reason'     => $reason,
				'form_alias' => $formAlias,
				'details'    => $details ? json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null,
			]);
		} catch (\Throwable $e) {
			$this->logger->error('AntiSpam DB Log failed: ' . $e->getMessage());
		}
	}

	private function logOnce(string $key, int $ttlSec, callable $fn): void
	{
		try {
			$this->cache->get($key, function (ItemInterface $item) use ($ttlSec, $fn) {
				$item->expiresAfter($ttlSec);
				$fn();

				return 1;
			});
		} catch (\Throwable) {
			// ignore
		}
	}

	private function isSpamMessageField(Widget $widget): bool
	{
		// Wichtig: Wenn dein Nachricht-Feld anders heißt, hier ergänzen.
		return \in_array($widget->name, ['message', 'nachricht', 'comment', 'msg', 'text'], true);
	}

	/* =========================================================
	 * Kernel Request (optional)
	 * =======================================================*/

	#[AsEventListener(event: 'kernel.request', priority: 255)]
	public function onKernelRequest(RequestEvent $event): void
	{
		if (!$event->isMainRequest()) {
			return;
		}

		$request = $event->getRequest();

		// no-op: placeholder for future request-level checks
		if (str_starts_with($request->getPathInfo(), '/contao')) {
			return;
		}
	}

	/* =========================================================
	 * compileFormFields
	 * =======================================================*/

	#[AsHook('compileFormFields')]
	public function compileFormFields(array $fields, string $formId, Form $form): array
	{
		if (!$this->isOne($form->lumas_antispam_enable ?? null)) {
			return $fields;
		}

		$request = $this->requestStack->getCurrentRequest();

		if (!$request || !$request->hasSession()) {
			return $fields;
		}

		$session = $request->getSession();
		$ip = $this->normalizeIp($request->getClientIp());

		if ($ip === null) {
			return $fields;
		}

		$formKey   = $this->getFormKey($request, $formId);
		$formAlias = $this->getFormAliasForLogging($form, $formId);

		// Session block => hide form (throttled log)
		$stateKey = 'lumas_antispam_state_' . $formKey;
		$state = $session->get($stateKey, ['invalidCount' => 0, 'blockedAt' => null, 'lastMarker' => null]);

		$blockTimeMin = (int) $this->getSetting('blockTime', $form);
		$blockTimeSec = max(1, $blockTimeMin) * 60;

		if (($state['blockedAt'] ?? null) !== null) {
			$age = time() - (int) $state['blockedAt'];

			if ($age < $blockTimeSec) {
				$logKey = 'lumas_antispam_sb_get_' . $formKey . '_' . md5($session->getId());
				$this->logOnce($logKey, 60, function () use ($ip, $formAlias, $request, $blockTimeSec, $age) {
					$this->logOnly($ip, 'SESSION_BLOCK_ACTIVE_FORM_HIDDEN', $formAlias, [
						'remaining' => max(0, $blockTimeSec - $age),
						'uri'       => $request->getRequestUri(),
						'ua'        => (string) $request->headers->get('User-Agent', ''),
					]);
				});

				// VERHINDERT DIE CONTAO-FALLE: Niemals [] bei POST zurückgeben!
				if ($request->isMethod('POST')) {
					throw new AccessDeniedHttpException('Session is temporarily blocked.');
				}

				return [];
			}

			// expired => reset
			$session->set($stateKey, ['invalidCount' => 0, 'blockedAt' => null, 'lastMarker' => null]);
		}

		// IP block => hide form ONLY if enforcement is enabled (throttled log)
		if ($this->isOne($this->getSetting('ip_block', $form)) && $this->isBlockedGlobal($ip)) {
			$logKey = 'lumas_antispam_ip_get_' . $formKey . '_' . md5($session->getId());
			$this->logOnce($logKey, 120, function () use ($ip, $formAlias, $request) {
				$this->logOnly($ip, 'IP_BLOCK_ACTIVE_FORM_HIDDEN', $formAlias, [
					'uri' => $request->getRequestUri(),
					'ua'  => (string) $request->headers->get('User-Agent', ''),
				]);
			});

			// VERHINDERT DIE CONTAO-FALLE: Niemals [] bei POST zurückgeben!
			if ($request->isMethod('POST')) {
				$this->logOnly($ip, 'BLOCKED_IP_POST_ATTEMPT', $formAlias, ['ua' => $request->headers->get('User-Agent')]);
				throw new AccessDeniedHttpException('IP is globally blocked.');
			}

			return [];
		}

		// Start time for minDelay:
		// IMPORTANT: set ONLY on GET and ONLY if not existing (avoid "TOO_FAST always")
		if (!$request->isMethod('POST')) {
			$map = $session->get('lumas_antispam_form_start', []);

			if (!isset($map[$formKey])) {
				$map[$formKey] = time();
				$session->set('lumas_antispam_form_start', $map);
			}
		}

		return $fields;
	}

	/* =========================================================
	 * validateFormField
	 * =======================================================*/

	#[AsHook('validateFormField')]
	public function __invoke(Widget $widget, string $formId, array $formData, Form $form): Widget
	{
		if (!$this->isOne($form->lumas_antispam_enable ?? null)) {
			return $widget;
		}

		$request = $this->requestStack->getCurrentRequest();

		if (!$request || !$request->hasSession()) {
			return $widget;
		}

		$session = $request->getSession();
		$ip = $this->normalizeIp($request->getClientIp());

		if ($ip === null) {
			return $widget;
		}

		$formKey   = $this->getFormKey($request, $formId);
		$formAlias = $this->getFormAliasForLogging($form, $formId);

		// IMPORTANT: If this submit was already marked as spam/blocked,
		// enforce an error on EVERY field to prevent Contao success flow (redirect/NC).
		if (($this->processedForms[$formKey] ?? null) === true) {
			$widget->addError('Ihre Nachricht hat die Spamschutzkriterien nicht bestanden.');

			return $widget;
		}

		// --- 1. HARTE IP-SPERRE (Sofort-Abbruch für bekannte Spammer als Fallback) ---
		if ($this->isOne($this->getSetting('ip_block', $form)) && $this->isBlockedGlobal($ip)) {
			$this->processedForms[$formKey] = true;
			$this->logOnly($ip, 'BLOCKED_IP_POST_ATTEMPT', $formAlias, [
				'ua' => $request->headers->get('User-Agent'),
				'uri' => $request->getRequestUri()
			]);
			throw new AccessDeniedHttpException('Invalid session state. Submit denied.');
		}

		// --- 2. DIRECT POST PROTECTION (Killer für Lutz-Rae Bot) ---
		$startMap = $session->get('lumas_antispam_form_start', []);
		$startTime = (int) ($startMap[$formKey] ?? 0);

		if ($startTime === 0) {
			$this->logOnly($ip, 'DIRECT_POST_ATTEMPT', $formAlias, [
				'ua' => $request->headers->get('User-Agent'),
				'uri' => $request->getRequestUri()
			]);

			// 2. IP sofort auf die schwarze Liste setzen (Reputation erhöhen)
			if ($this->isOne($this->getSetting('ip_block', $form))) {
				$this->updateReputation($ip);
			}

			// 3. HARTER ABBRUCH: Keine Mail, kein NC, keine weitere Verarbeitung.
			throw new AccessDeniedHttpException('Invalid session state. Submit denied.');
		}

		$isMessageField = $this->isSpamMessageField($widget);

		// Session state
		$stateKey = 'lumas_antispam_state_' . $formKey;
		$state = $session->get($stateKey, ['invalidCount' => 0, 'blockedAt' => null, 'lastMarker' => null]);

		// 3) Session block enforcement (always)
		$blockTimeSec = max(1, (int) $this->getSetting('blockTime', $form)) * 60;

		if (($state['blockedAt'] ?? null) !== null) {
			$age = time() - (int) $state['blockedAt'];

			if ($age < $blockTimeSec) {
				$this->processedForms[$formKey] = true;

				$this->logOnly($ip, 'SESSION_BLOCK_ACTIVE_ON_POST', $formAlias, [
					'form_key'     => $formKey,
					'remaining'    => max(0, $blockTimeSec - $age),
					'uri'          => $request->getRequestUri(),
					'ua'           => (string) $request->headers->get('User-Agent', ''),
					'email'        => $this->extractEmail($formData, $request),
					'invalidCount' => (int) ($state['invalidCount'] ?? 0),
				]);

				$widget->addError('Ihre Nachricht hat die Spamschutzkriterien nicht bestanden.');

				return $widget;
			}
		}

		// 4) Content checks + attempt logging happen ONLY on message field (=> 1 log per submit)
		if ($isMessageField) {
			$reason = $this->checkSpam(
				$widget,
				$request,
				$startTime,
				$startTime > 0,
				(int) $this->getSetting('minDelay', $form),
				(int) $this->getSetting('stopwordCount', $form),
				(string) $this->getSetting('language', $form),
				(int) $this->getSetting('minLen', $form),
			);

			if ($reason !== null) {
				$this->processedForms[$formKey] = true;

				// Count strikes once per POST submit (marker)
				$marker = $this->makeSubmitMarker($formKey, $session, $request);

				$blockSetNow = false;

				if (($state['lastMarker'] ?? null) !== $marker) {
					$state['invalidCount'] = (int) ($state['invalidCount'] ?? 0) + 1;
					$state['lastMarker'] = $marker;

					// Block ab 3. Fehlversuch (2 sind erlaubt)
					if (
						$state['invalidCount'] >= (self::SESSION_INVALID_THRESHOLD + 1)
						&& ($state['blockedAt'] ?? null) === null
					) {
						$state['blockedAt'] = time();
						$blockSetNow = true;
					}

					$session->set($stateKey, $state);
				}

				// Log THIS attempt (always)
				$this->logAttempt($ip, $form, $reason, $widget, $formAlias, $request, $formData, $formKey, $state, $startTime, (int) $this->getSetting('minDelay', $form));

				// Log the moment the session block is set (extra explicit)
				if ($blockSetNow) {
					$this->logOnly($ip, 'SESSION_BLOCK_SET', $formAlias, [
						'form_key'     => $formKey,
						'uri'          => $request->getRequestUri(),
						'ua'           => (string) $request->headers->get('User-Agent', ''),
						'email'        => $this->extractEmail($formData, $request),
						'invalidCount' => (int) ($state['invalidCount'] ?? 0),
						'blockTimeMin' => (int) $this->getSetting('blockTime', $form),
					]);
				}

				// Reputation counts for EVERY error, independent of session/IP enforcement
				$this->updateReputation($ip);

				$widget->addError('Ihre Nachricht hat die Spamschutzkriterien nicht bestanden.');
			} else {
				$this->processedForms[$formKey] = false;
			}
		}

		return $widget;
	}

	/* =========================================================
	 * Core checks
	 * =======================================================*/

	private function isBlockedGlobal(string $ip): bool
	{
		$ck = $this->cacheKeyForIp($ip);

		try {
			return (bool) $this->cache->get($ck, function (ItemInterface $item) use ($ip) {
				$item->expiresAfter(self::STATUS_TTL_SEC);

				$status = $this->db->fetchAssociative(
					'SELECT is_hard_blocked,is_whitelisted,is_permanent,block_count,tstamp,ip_block_ttl
					 FROM tl_lumas_antispam_ip_block WHERE ip_address = ?',
					[$ip],
				);

				if (!$status) {
					return false;
				}

				if ($this->isOne($status['is_whitelisted'] ?? 0)) {
					return false;
				}

				if ($this->isOne($status['is_permanent'] ?? 0)) {
					return true;
				}

				$ttl = (int) ($status['ip_block_ttl'] ?? 24);

				if (!empty($status['tstamp']) && time() - (int) $status['tstamp'] > $ttl * 3600) {
					return false;
				}

				return $this->isOne($status['is_hard_blocked'] ?? 0)
					|| (int) ($status['block_count'] ?? 0) >= self::GLOBAL_BLOCK_THRESHOLD;
			});
		} catch (\Throwable) {
			return false;
		}
	}

	private function checkSpam(
		Widget $widget,
		Request $request,
		int $start,
		bool $hadTime,
		int $minDelay,
		int $minStop,
		string $lang,
		int $minLen,
	): ?string {
		// Honeypot
		if ((string) $request->request->get('hp_field', '') !== '') {
			return 'HONEYPOT';
		}

		// Too fast
		if ($hadTime) {
			$delta = time() - $start;

			if ($delta < $minDelay) {
				return 'TOO_FAST';
			}
		}

		// Too short
		$text = trim((string) ($widget->value ?? ''));

		if (mb_strlen($text) < $minLen) {
			return 'TOO_SHORT';
		}

		// Language mismatch
		if (!$this->isCorrectLanguage($text, $lang, $minStop)) {
			return 'LANGUAGE_MISMATCH';
		}

		return null;
	}

	private function isCorrectLanguage(string $text, string $lang, int $minStop): bool
	{
		$text = (string) preg_replace('/https?:\/\/[^\s]+/iu', '', $text);
		$tokens = preg_split('/\P{L}+/u', mb_strtolower($text), -1, PREG_SPLIT_NO_EMPTY);

		if (!$tokens) {
			return false;
		}

		$list = $this->stopwords[$lang] ?? $this->stopwords['de'];
		$set = array_flip($list);

		$hits = 0;

		foreach ($tokens as $t) {
			if (isset($set[$t]) && ++$hits >= $minStop) {
				return true;
			}
		}

		return false;
	}

	/* =========================================================
	 * Logging
	 * =======================================================*/

	private function logAttempt(
		string $ip,
		Form $form,
		string $reason,
		Widget $widget,
		string $formAlias,
		Request $request,
		array $formData,
		string $formKey,
		array $state,
		int $start,
		int $minDelay,
	): void {
		$now = time();
		$delta = $start > 0 ? ($now - $start) : null;

		$this->logOnly($ip, $reason, $formAlias, [
			'form_key'      => $formKey,
			'field'         => $widget->name,
			'email'         => $this->extractEmail($formData, $request),
			'uri'           => $request->getRequestUri(),
			'ua'            => (string) $request->headers->get('User-Agent', ''),
			'lang'          => (string) $this->getSetting('language', $form),
			'invalidCount'  => (int) ($state['invalidCount'] ?? 0),
			'session_block' => (($state['blockedAt'] ?? null) !== null) ? 1 : 0,

			// timing debug (helps prove TOO_FAST)
			'start'    => $start ?: null,
			'now'      => $now,
			'delta'    => $delta,
			'minDelay' => $minDelay,
		]);
	}

	/* =========================================================
	 * Reputation / IP block duration logic
	 * =======================================================*/

	private function updateReputation(string $ip): void
	{
		try {
			$now = time();

			$row = $this->db->fetchAssociative(
				'SELECT id, reputation_score FROM tl_lumas_antispam_ip_block WHERE ip_address=?',
				[$ip],
			);

			$score = 1;

			if ($row) {
				$score = (int) ($row['reputation_score'] ?? 0) + 1;
			}

			// TTL in hours according to step logic
			if ($score < 5) {
				$ttlHours = 24;
			} elseif ($score < 10) {
				$ttlHours = 24;
			} else {
				$step = intdiv($score, 5) - 1; // 10->1, 15->2, 20->3 ...
				$ttlHours = 120 * $step;
			}

			if (!$row) {
				$this->db->insert('tl_lumas_antispam_ip_block', [
					'ip_address'       => $ip,
					'tstamp'           => $now,
					'block_count'      => $score,
					'reputation_score' => $score,
					'ip_block_ttl'     => $ttlHours,
				]);
			} else {
				$this->db->update(
					'tl_lumas_antispam_ip_block',
					[
						'tstamp'           => $now,
						'block_count'      => $score,
						'reputation_score' => $score,
						'ip_block_ttl'     => $ttlHours,
					],
					['id' => (int) $row['id']],
				);
			}

			// clear cached status (CacheInterface key)
			try {
				$this->cache->delete($this->cacheKeyForIp($ip));
			} catch (\Throwable) {
				// ignore
			}
		} catch (\Throwable $e) {
			$this->logger->error('AntiSpam updateReputation failed: ' . $e->getMessage());
		}
	}
}
