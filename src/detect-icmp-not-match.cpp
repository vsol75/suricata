#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-icmp-not-match.h"



extern "C"
{

/**
 * \brief This function is used to match HELLOWORLD rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectHelloWorldData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectIcmpNotMatchMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
    int ret = 0;
	std::cout << "MyIcmp matching" << std::endl;

	FlowHandlePacket(t, , p);

    return ret;
}


/**
 * \brief this function is used to get the parsed helloworld data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param helloworldstr pointer to the user provided helloworld options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIcmpNotMatchSetup (DetectEngineCtx *de_ctx, Signature *s, char* options)
{
	std::cout << "MyIcmp setup" << std::endl;

	return 0;
}


/**
 * \brief this function will free memory associated with DetectHelloWorldData
 *
 * \param ptr pointer to DetectHelloWorldData
 */
void DetectIcmpNotMatchFree(void *ptr)
{
	std::cout << "MyIcmp free" << std::endl;
	// Do nothing at the moment
}
/**
 * \brief Registration function for helloworld: keyword
 */
void DetectHelloWorldRegister(void) {
    sigmatch_table[DETECT_ICMP_NOT_MATCH].name = "IcmpNotMatch";
    sigmatch_table[DETECT_ICMP_NOT_MATCH].desc = "<todo>";
    sigmatch_table[DETECT_ICMP_NOT_MATCH].url = "<todo>";
    sigmatch_table[DETECT_ICMP_NOT_MATCH].Match = DetectIcmpNotMatchMatch;
    sigmatch_table[DETECT_ICMP_NOT_MATCH].Setup = DetectIcmpNotMatchSetup;
    sigmatch_table[DETECT_ICMP_NOT_MATCH].Free = DetectIcmpNotMatchFree;
    sigmatch_table[DETECT_ICMP_NOT_MATCH].RegisterTests = NULL;
}

}
