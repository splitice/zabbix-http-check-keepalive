#include "sysinc.h"
#include "module.h"
#include "hck_engine.h"

extern "C" {
	#include "common.h"
	#include "log.h"
	int    zbx_module_hck_check(AGENT_REQUEST *request, AGENT_RESULT *result);
}


static ZBX_METRIC keys[] =
/* KEY               FLAG           FUNCTION                TEST PARAMETERS */
{
	{ "hck.check", CF_HAVEPARAMS, (int(*)())zbx_module_hck_check, "203.13.161.80,80" },
	{ NULL }
};

void hck_log(int level, const char *fmt, ...){
	char errbuf[1024];
	
	va_list args;
    va_start(args, fmt);
    vsprintf(errbuf, fmt, args);
    va_end(args);
	
	zabbix_log(level, "%s", errbuf);
}


extern "C" {
	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_api_version                                           *
	*                                                                            *
	* Purpose: returns version number of the module interface                    *
	*                                                                            *
	* Return value: ZBX_MODULE_API_VERSION_ONE - the only version supported by   *
	*               Zabbix currently                                             *
	*                                                                            *
	******************************************************************************/
	int    zbx_module_api_version()
	{
		return ZBX_MODULE_API_VERSION_ONE;
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_item_timeout                                          *
	*                                                                            *
	* Purpose: set timeout value for processing of items                         *
	*                                                                            *
	* Parameters: timeout - timeout in seconds, 0 - no timeout set               *
	*                                                                            *
	******************************************************************************/
	void    zbx_module_item_timeout(int timeout)
	{
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_item_list                                             *
	*                                                                            *
	* Purpose: returns list of item keys supported by the module                 *
	*                                                                            *
	* Return value: list of item keys                                            *
	*                                                                            *
	******************************************************************************/
	ZBX_METRIC    *zbx_module_item_list()
	{
		return keys;
	}

	int hck_fd = -1;

	int    zbx_module_hck_check(AGENT_REQUEST *request, AGENT_RESULT *result)
	{
		unsigned short res;
		char *param1, *param2;
		char buffer[1];

		if (hck_fd == -1)
		{
			hck_fd = connect_to_hck();
		}
		else if (send(hck_fd, &buffer, 0, 0) == -1)
		{
			close(hck_fd);
			hck_fd = connect_to_hck();
		}

		if (hck_fd == -1){
			SET_MSG_RESULT(result, strdup("Unable to connect to worker process"));
			return SYSINFO_RET_FAIL;
		}

		param1 = get_rparam(request, 0);
		param2 = get_rparam(request, 1);

		res = execute_check(hck_fd, param1, param2);

		//an error occured
		if (res > 1){
			close(hck_fd);
			hck_fd = -1;

			res = 0;
		}

		SET_UI64_RESULT(result, res);

		return SYSINFO_RET_OK;
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_init                                                  *
	*                                                                            *
	* Purpose: the function is called on agent startup                           *
	*          It should be used to call any initialization routines             *
	*                                                                            *
	* Return value: ZBX_MODULE_OK - success                                      *
	*               ZBX_MODULE_FAIL - module initialization failed               *
	*                                                                            *
	* Comment: the module won't be loaded in case of ZBX_MODULE_FAIL             *
	*                                                                            *
	******************************************************************************/
	int    zbx_module_init()
	{
		if (fork() == 0){
			zbx_setproctitle("zabbix_proxy: http check keepalive #1");
			processing_thread();
			exit(1);
		}

		return ZBX_MODULE_OK;
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_uninit                                                *
	*                                                                            *
	* Purpose: the function is called on agent shutdown                          *
	*          It should be used to cleanup used resources if there are any      *
	*                                                                            *
	* Return value: ZBX_MODULE_OK - success                                      *
	*               ZBX_MODULE_FAIL - function failed                            *
	*                                                                            *
	******************************************************************************/
	int    zbx_module_uninit()
	{
		return ZBX_MODULE_OK;
	}
}