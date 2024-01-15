{"version":3,"file":"audioplayer.bundle.map.js","names":["exports","ui_fonts_opensans","main_polyfill_intersectionobserver","ui_vue","main_core_events","_State","Object","freeze","play","pause","stop","none","BitrixVue","component","props","id","default","src","autoPlayNext","background","data","isDark","preload","loaded","loading","playAfterLoad","state","progress","progressInPixel","seek","timeCurrent","timeTotal","created","this","preloadRequestSent","registeredId","registerPlayer","$Bitrix","eventEmitter","subscribe","onPlay","onStop","onPause","onPreload","mounted","getObserver","observe","$refs","body","beforeDestroy","unregisterPlayer","unsubscribe","unobserve","watch","value","preloadNext","methods","loadFile","arguments","length","undefined","source","clickToButton","setPosition","event","pixelPerPercent","track","offsetWidth","setProgress","currentTime","seeking","offsetX","percent","pixel","Math","round","formatTime","second","floor","hour","minute","toString","padStart","_this","registry","Data","get","babelHelpers","toConsumableArray","Set","concat","filter","sort","a","b","set","_this2","playNext","_this3","nextId","slice","emit","start","_this4","getData","initiator","audioEventRouter","eventName","duration","console","error","_this5","observer","IntersectionObserver","entries","forEach","entry","isIntersecting","target","threshold","computed","State","seekPosition","isMobile","progressPosition","labelTime","time","UA","navigator","userAgent","toLowerCase","includes","template","window","BX","Event"],"sources":["audioplayer.bundle.js"],"mappings":"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"}