{"version":3,"file":"sidepanel.menu.bundle.map.js","names":["this","BX","UI","exports","ui_fonts_opensans","main_popup","main_core_events","main_core","_","t","_t","_list","babelHelpers","classPrivateFieldLooseKey","_node","_sync","_addSilent","Collection","EventEmitter","constructor","options","super","Object","defineProperty","value","_addSilent2","writable","setEventNamespace","setItems","items","setActiveFirstItem","item","list","setActive","getCollection","getActiveItem","filter","isActive","syncActive","excludeItem","classPrivateFieldLooseBase","otherItem","forEach","isEmpty","emit","add","itemOptions","render","get","id","getId","change","foundItem","find","remove","map","length","hasActive","recursively","has","some","Tag","innerHTML","appendChild","active","Item","push","subscribe","data","setTimeout","_$1","_t$1","_t2","_t3","_id","_label","_active","_notice","_onclick","_collection","_node$1","_actions","_emitChange","_handleClick","_showActionMenu","_showActionMenu2","_handleClick2","_emitChange2","setLabel","label","setNotice","notice","setId","setClickHandler","onclick","setActions","actions","event","mode","handler","getLabel","getClickHandler","hasNotice","hasActions","Type","isUndefined","Dom","classes","actionText","Loc","getMessage","join","bind","safe","Event","querySelector","append","type","preventDefault","stopPropagation","isFunction","apply","actionsMenu","getPopupWindow","close","targetIcon","currentTarget","addClass","parentNode","Menu","bindElement","action","addMenuItem","text","menuItem","getMenuWindow","removeClass","destroy","show","_$2","_t$2","_node$2","itemsNode","renderTo","target","node","SidePanel","Main"],"sources":["sidepanel.menu.bundle.js"],"mappings":"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"}