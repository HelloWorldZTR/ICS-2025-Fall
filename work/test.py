
# v_line is the function name, pg_info is a json-like dict
def v_line(pg_info):
    points = []

    # Extract points
    for key, item in pg_info.items():
        if 'rdf:type' in item and 'common_base:buildingBlock' in item['rdf:type']:
            try:
                # round as in your earlier code
                px = round(item['common_base:coordinateX'][0], 2)
                py = round(item['common_base:coordinateY'][0], 2)
                color = item['common_base:hasColour'][0]
            except Exception:
                # skip malformed entries
                continue
            points.append((px, py, color))

    n = len(points)

    ks = []
    for p1 in points:
        for p2 in points:
            if p1 == p2:
                continue
            else:
                if p1[0] == p2[0]:  # vertical line check
                    k = 114514 # special value in case all points are vertical
                else:
                    k = (p2[1] - p1[1]) / (p2[0] - p1[0])
                ks.append(k)

    avg_k = sum(ks) / len(ks) if ks else 0
    
    isLine = True
    for k in ks:
        if abs(k - avg_k) > 0.1:
            isLine = False
    
    isSameColor = True
    points.sort(key = lambda x: (x[0], x[1]))
    # points of the same color should be continuous
    colors = set(p[2] for p in points)
    for color in colors:
        started = False
        ended = False
        for p in points:
            if p[2] == color:
                if ended:
                    isSameColor = False
                    break
                else:
                    started = True
            else:
                if started:
                    ended = True
        if not isSameColor:
            break

        
    return isLine and isSameColor