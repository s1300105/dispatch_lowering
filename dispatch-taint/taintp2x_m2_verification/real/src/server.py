#server.py
'''
SecurityNik Vulnerable MCP Server
https://www.securitynik.com
'''

from mcp.server.fastmcp import FastMCP
import subprocess
import logging

# Setup logging so we can see the activity as we go along
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[ 
        logging.FileHandler('mcp-server.log')
    ])

logger = logging.getLogger(__name__)

# Setup the MCP server
mcp = FastMCP(name='SecurityNik Vulnerable MCP Server for testing')


@mcp.tool()
def read_file(path: str) -> str:
    ''' Reads file from disk '''
    logger.info(f'🚀 [TOOL CALL]: read_file path={path}')
    with open(file=path, mode='r') as fp:
        data = fp.read()

    logger.info(f' [TOOL RESULT]: read_file bytes={len(data)}')
    return data
    
    
@mcp.tool()
def run_command(cmd: str) -> str:
    '''Runs a shell command '''
    logger.info(f'🚀 [TOOL CALL]: run_command command={cmd}')
    result = subprocess.check_output(cmd, shell=True)
    logger.info(f' [TOOL RESULT]: run_command bytes={len(result)}')
    return result.decode()


if __name__ == '__main__':

    logger.info(f'🚀 Running SecurityNik vulnerable MCP server ...')
    mcp.run(transport='stdio')