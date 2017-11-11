import lib_clusters
import os

testsArray = {
"tl": [
	"ccengine_run_from_directory_tests.cmd",
	"ccengine_run_test_daemon_unit.cmd",
	"ccengine_run_test_msg_server.cmd",
	"ccengine_run_test_params.cmd",
	"ccengine_run_test_persistence.cmd",
	"ccenginefirun_testcore.cmd",
	"ccengine_run_tests.cmd",
	"ccengine_run_trades.cmd",
	"ccengine64Bit_run_cceapi_tests.cmd",
	"cengine64Bit_run_tests.cmd",
	"ProcessFXTLogFileForCCEngine.cmd",
	"RunFXTReconciler.cmd",
	"RunFXTTradeExtracts.cmd",
	"RunSAS .bat",
	"ScenarioInvestigation.sh",
	"tmp_5037.log",
	"tmp_5038.log",
	"tmpraw_5037.log",
	"tmpraw_5038.log",
	"tmpsort_5037.log",
	"tmpsort_5038.log",
	"toto",
	"fxtImporter_ETS_CDP_Oo00_47_[13720]_debug.log",
	"cce_find_calc;msg_conn_attempts.cmd",
	"cce_find_calc_msgs.cmd",
	"cce_find_non_cce_team_calc_msgs.cmd",
	"CCEngine_FXTDeal_CC_Calculator.xlsx",
	"ccengine_run_cce_msg_svr.cmd",
	"ccengine_run_cceapi_tests.cmd",],
"t2": [
	"cpprest14od_2_8.dll",
	"cpprestl4od_2_9.dll",
	"cpprestl4od_2_9.pdb",
	"Echo.dll",
	"EchoApiCmd.exe",
	"EchoClient.exe",
	"EchoCoherence.dll",
	"EchoXL.dll",
	"lnk{8D44DD9B-DE84-EBSC-AFFD-5BDO5Ao3F4F6}.tmp"
	"TestScenarioAnalysis.exe",
	"TestScenarioAnalysis.idb",
	"TestScenarioAnalysis.ilk",
	"TestScenarioAnalysis.pdb",
	"boost_atomic-vc140-mt-gd-l_60.dll",
	"boost_chrono-vc140-mt-gd-1_60.dll",
	"boost_container-vc140-mt-gd-1_60.dll",
	"boost_context-vc140-mt-gd-1_60.dll",
	"boost_coroutine-vc140-mt-gd-l_60.dll",
	"boost_date_time-vc140-mt-gd-1_60.dll",
	"boost_filesystem-vc140-mt-gd-1_60.dll",
	"boost_graph-vc140-mt-gd-1_60.dll",
	"boost_iostreams-vc140-mt-gd-l_60.dll",
	"boost_locale-vc140-mt-gd-l_60.dll",
	"boost_log_setup-vc140-mt-gd-1_60.dll",
	"boost_log-vc140-mt-gd-1_60.dll",
	"boost_math_c99f-vc140-mt-gd-1_60.dll",
	"boost_math_c99l-vc140-mt-gd-l_60.dll",
	"boost_math_c99-vc140-mt-gd-1_60.dll",
	"boost_math_tr1f-vc140-mt-gd-l_60.dll",
	"boost_math_trll-vc140-mt-gd-1_60.dll",
	"boost_math_trl-vc140-mt-gd-l_60.dll",
	"boost_prg_exec_monitor-vc140-mt-gd-l_60.dll",
	"boost_program;options-vc140-mt-gd-1_60.dll",
	"boost_python-vc140-mt-gd-l_60.dll",
	"boost_random-vc140-mt-gd-1_60.dll",
	"boost_regex-vc140-mt-gd-l_60.dll",
	"boost_serialization-vc140-mt-gd-1_60.dll",
	"boost_signals-vc140-mt-gd-l_60.dll",
	"boost_system-vc140-mt-gd-1_60.dll",
	"boost_thread-vc140-mt-gd-l_60.dll",
	"boost_timer-vc140-mt-gd-l_60.dll",
	"boost_type_erasure-vc140-mt-gd-l_60.dll",
	"boost_unit_testfiframework-vc140-mt-gd-1_60.dll",
	"boost_wave-vc140-mt-gd-l_60.dll",
	"boost_wserialization-vc140-mt-gd-l_60.dll",
	"CCE.dll",
	"CCE.pdb",
	"cce_echo_ponfiguration.csv",
	"cce_http_configuration.csv",
	"cce_msg_configuration.csv",
	"cce_sas_configuration.csv",
	"cceflsvc_configuration.csv",
	"cce_trade_configuration.csv",
	"CCEApiTest.Build.CppClean.log",
	"CCEApiTest.exe",
	"CCEApiTest.idb",
	"CCEApiTest.ilk",
	"CCEApiTest.log",
	"CCEApiTest.pdb",
	"CCEApiTestMain.obj",
	"CCEConfigurationTest.csv",
	"CCEHTTPService.exe",
	"CCEHTTPService.idb",
	"CCEHTTPService.ilk",
	"CCEHTTPService.pdb",
	"CCEMessageServer.exe",
	"CCEMessageServer.idb",
	"CCEMessageServer.ilk",
	"CCEMessageServer.pdb",
	"CCEMessageService.exe",
	"CCEMessageService.idb",
	"CCEMessageService.ilk",
	"CCEMessageService.pdb",
	"CCEScenarioAnalysis.dll",
	"CCEScenarioAnalysis.idb",
	"CCEScenarioAnalysis.ilk",
	"CCEScenarioAnalysis.pdb",
	"CCEScenarioAnalysisService.exe",
	"CCEScenarioAnalysisService.idb",
	"CCEScenarioAnalysisService.ilk",
	"CCEScenarioAnalysisService.pdb",
	"CCETest.bsc",
	"CCETest.exe",
	"CCETest.pdb",
	"CCETestCore.exe",
	"CCETestCore.idb",
	"CCETestCore.ilk",
	"CCETestCore.pdb",
	"CCETestDaemon.exe",
	"CCETestDaemon.idb",
	"CCETestDaemon.ilk",
	"CCETestDaemon.pdb",
	"CCETestService.exe",
	"CCETestService.idb",
	"CCETestService.ilk",
	"CCETestService.pdb",
	"CCETrade.bsc",
	"CCETrade.exe",
	"CCETrade.pdb",
	"CCEUnitTest.obj",
	"Common.Logging.DLL",
] }

#Problems quand on utilise _ comme delimiteur avec tri recursif.
#depth=1 utilise "boost".
#Mais depth=2 produit ceci.
#Malheureusement il faudrait considerer les lignes globalement.
#Avoir des passes independantes en fonction du delimiteur, ne va pas aider
#car ca va creer des clusters qui n'existent pas.
#
#Faire un pretraitement en chercher si toutes les chaines ont une sous-chains
#en commun et la retirer ? Tres lent et pas suffisant.
#Ou alors splitter de facon plus appropriee, de facon hierarchique.
#On ne se contente pas de l'index numerique. L'index doit exprimer logiquement
#ou se trouve la sous-chaine.
#

#On decoupe recursivement mais tous les morceaux sont mis dans le split avec
#la chaine d'origine:
#boost_date_time-vc140-mt-gd-l_60.dll
#d.0" : "boost_date_time-vc"
#d. 1" : ll_mt_gd_"
#d.2" : "_11
#d.3" : ".dll"
#11: "_0 II : "boost"
#1" : "date"
#2" : "time-vc140-mt-gd-1_60.dll"
#-O" : "boost_datthime"
#-1" : "VCl40"
#2" : "mt"
#3" : "gd"
#-4" : "l_60.dll"
#
#et ensuite:
#d.0 -0" : "boost_date_time"
#d.0 -1" : "vc"
#
#d.0 -0 _0" : "boost"
#d.0 -0 _1" : "date"
#d.0 -O _2" : "time"
#
#C est tres gourmand.
#Est-ce que l'ordre des delimiteurs importe
#Ou bien devrait-on simplement dire que c'est le X-ieme element pour tel separateur
#
#mt
#boost_atomic-vc140-mt-gd-1_60.dll
#boost_chrono-vc140-mt-gd-1_60.dll
#vc
#boost_date_time-vc140-mt-gd-1_60.dll
#boost_log_setup-vc140-mt-gd-l_60.dll

# Ou plutot:
# Chaque mot du split[] est equipe des deux delimiteurs avant et apres.
# D'un index des delimiteurs uniques
# ainsi que d'un index a l interieur de la sequence de delimiteurs identiques.
# Exemple:
# "boost_prg_exec_monitor-vc140-mt-gd-1_60.dll"
# boost     _  0 0
# prg     _ _  0 1
# exec    _ _  0 2
# monitor _ -  0 3
# vc      - d  1 0
# mt      d -  2 0
# gd      - -  2 `
#         - d  3 0
#         d _  4 0
#         _ d  5 0
#         d .  6 0
# dll     .    7 0
#
# Ca peut etre aussi pas mal de garder les sequences numeriques.
# On tourne autour de la meme idee:
# (1) Indexer des petits segments pour pouvoir matcher ces segments avec d'autres chaines.
# (2) Mettre ensemble des segmentations d'origine diverses.
#
# Ca revient a dire par exemple:
# - Le deuxieme nombre est ...
# - un des mots (decoupes avec " ") de la seconde chaine alphanum (decoupee avec ".") est ...
#
# On va donc avoir un nouveau word_eligibility.

def CreateSolutions(lstWrds):
	dictClustl = lib_clusters.by_hash(lstWrds)
	print ("")
	print("")
	print("")
	dictClustersArrays = lib_clusters.by_columns(lstWrds)
	dictClustersArrays["by_hash"] = dictClustl
	dictClustersArrAll = dict(dictClustersArrays)
	for key in dictClustersArrays:
		crunchedClust = dict(lib_clusters.compress(dictClustersArrays[key]))
		dictClustersArrAll[key+".compress"] = crunchedClust
	return dictClustersArrAll

#Other parameters:
#(1) Maximum desired elements.
#(2) Recursive analysis to X levels.
#
#On peut legitimement demander la seconde ou troisieme solution.
#
def SelectSolutions(lstWrds,depth=1):
	dictClustersArrAll = CreateSolutions(lstWrds)
	print("SelectSolutions depth=%d szWords=%d numClusts=%d\n"%(depth,len(lstWrds),len(dictClustersArrAll)))
	bstKey = lib_clusters.get_best_crit1(dictClustersArrAll)
	# Maybe there is no usable solution.
	if not bstKey:
		return ( None,None)
	bestChoice = dictClustersArrAll[bstKey]
	if depth <= 1:
		return (bstKey,bestChoice)

	depth -= 1
	bestChoiceRecurs = dict()

	for keyClust in bestChoice:
		lstChoice = bestChoice[keyClust]
		# This tries to clusterize the sub-list, only if there are many elements.
		if len(lstChoice) > 3:
			(bstSubKey,bestSubChoice) = SelectSolutions(lstChoice,depth)
			if bstSubKey:
			# Maybe the result is not worth. We should rather use entropy.
				if len(bestSubChoice) > 2:
					bestChoiceRecurs[ keyClust + "." + bstSubKey ] = bestSubChoice
					continue

		# No change: No need to clusterize recursively.
		bestChoiceRecurs[ keyClust ] = lstChoice
	return (bstKey,bestChoiceRecurs)

def TestWords(sampleName,lstWrds):
	print ("\n\n\n\n" + ("    "*80) +"\n")
	print("SAMPLE=%s numWrds=%s"%(sampleName,len(lstWrds)))
	(bstKey,bestChoice) = SelectSolutions(lstWrds,3)
	print ("")
	print("BEST=%s"%bstKey)
	#print(bstIdx)
	lib_clusters.PrintCluster(bestChoice,False)

def TestFix():
	for key in testsArray:
		tstArr = testsArray[key]
		TestWords(key,tstArr)

def TestDir():
	mypath = "C:/tmp"
	#onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]

	onlyfiles = list(set([ fi[2][0] for fi in os.walk(mypath) if fi[2]]))
	#onlyfiles = onlyfiles[50:100]
	#print(onlyfiles)
	#exit(0)
	TestWords(mypath,onlyfiles)

TestDir()
TestFix()
#TestWords("t2",testsArray["t2"])