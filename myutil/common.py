import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, make_scorer, precision_score, recall_score, average_precision_score, roc_auc_score, precision_recall_curve, auc, roc_curve, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
# from IPython.display import display

def load_data(clean_dir, sample_size=1948, train_size=100000, val_size=100000, test_size=30000, train_size_malicious=0.7, file_type="parquet", verbose=True):
    # Read data
    if file_type == "parquet":
        df_benign = pd.read_parquet(f"{clean_dir}/all_benign.parquet")
        df_malicious = pd.read_parquet(f"{clean_dir}/all_malicious.parquet")
    elif file_type == "feather":
        df_benign = pd.read_feather(f"{clean_dir}/all_benign.feather")
        df_malicious = pd.read_feather(f"{clean_dir}/all_malicious.feather")
        
    attack_type = df_malicious.Label.copy()

    # Map label to attack type
    df_malicious.Label = df_malicious.Label.map({
        'DoS Hulk':'(D)DOS', 
        'PortScan':'Port Scan', 
        'DDoS':'(D)DOS', 
        'DoS slowloris':'(D)DOS', 
        'DoS Slowhttptest':'(D)DOS', 
        'DoS GoldenEye':'(D)DOS', 
        'SSH-Patator':'Brute Force', 
        'FTP-Patator':'Brute Force', 
        'Bot': 'Botnet', 
        'Web Attack \x96 Brute Force': 'Web Attack', 
        'Web Attack \x96 Sql Injection': 'Web Attack', 
        'Web Attack \x96 XSS': 'Web Attack',
        'Infiltration': 'Infiltration',
        'Heartbleed': 'Heartbleed',
        'Web Attack ï¿½ Brute Force': 'Web Attack',
        'Web Attack ï¿½ Sql Injection': 'Web Attack',
        'Web Attack ï¿½ XSS': 'Web Attack',

        # 2018
        'DDoS attacks-LOIC-HTTP': '(D)DOS',
        'DDOS attack-HOIC': '(D)DOS',
        'DoS attacks-Hulk': '(D)DOS',
        'DoS attacks-GoldenEye': '(D)DOS',
        'DoS attacks-Slowloris': '(D)DOS',
        'DDOS attack-LOIC-UDP': '(D)DOS',
        'DoS attacks-SlowHTTPTest': '(D)DOS', # Assuming this exists in data2
        'Bot': 'Botnet',
        'SSH-Bruteforce': 'Brute Force',
        'FTP-BruteForce': 'FTP-BruteForce', # Assuming this exists in data2
        'Brute Force -Web': 'Brute Force', # Grouping Web Brute force with others
        'Brute Force -XSS': 'Web Attack', # Keeping XSS as Web Attack
        'SQL Injection': 'Web Attack', # Assuming this exists in data2
        'Infilteration': 'Unknown' # Mapping Infiltration to Unknown
    })


    # Split benign data in train, validation, test split
    y_benign = np.ones(df_benign.shape[0])
    x_benign = df_benign.drop(columns=['Label', 'Timestamp', 'Destination Port'])

    x_benign_train, x_benign_valtest, y_benign_train, y_benign_valtest = train_test_split(x_benign, y_benign, train_size=train_size, random_state=42, shuffle=True)
    x_benign_val, x_benign_test, y_benign_val, y_benign_test = train_test_split(x_benign_valtest, y_benign_valtest, train_size=val_size, test_size=test_size, random_state=42, shuffle=True)

    # Split malicious data in train, test split
    train_idx, test_idx = sub_sample_train_test(df_malicious, attack_type, sample_size, train_size_malicious)
    y_multi = df_malicious.Label
    x_multi = df_malicious.drop(columns=['Label', 'Timestamp', 'Destination Port'])
    x_malicious_train, x_malicious_test, y_malicious_train, y_malicious_test = (x_multi.iloc[train_idx], x_multi.iloc[test_idx], y_multi.iloc[train_idx], y_multi.iloc[test_idx])
    attack_type_train, attack_type_test = (attack_type.iloc[train_idx], attack_type.iloc[test_idx])
    
    if verbose:
        overview = {}
        overview[('Benign', 'Benign')] = {
            "#Original": df_benign.shape[0], 
            "#Sampled": x_benign_train.shape[0] + x_benign_val.shape[0] + x_benign_test.shape[0], 
            "#Train": x_benign_train.shape[0], 
            "#Validation": x_benign_val.shape[0], 
            '%Validation': 100,
            "#Test": x_benign_test.shape[0],
            '%Test': 100,
        }
        for attack_class in np.unique(y_multi):
            attack_impl_train_count = attack_type_train[y_malicious_train == attack_class].value_counts()
            attack_impl_test_count = attack_type_test[y_malicious_test == attack_class].value_counts()
            for attack_impl in np.unique(np.concatenate([attack_impl_test_count.keys(), attack_impl_train_count.keys()])):
                train_count = attack_impl_train_count[attack_impl] if attack_impl in attack_impl_train_count else 0
                test_count = attack_impl_test_count[attack_impl] if attack_impl in attack_impl_test_count else 0
                overview[(attack_class, attack_impl)] = {
                    "#Original": (attack_type == attack_impl).sum(), 
                    "#Sampled": train_count + test_count, 
                    "#Train": 0, 
                    "#Validation": train_count if sum(attack_impl_train_count) > 0 else '-', 
                    '%Validation': train_count / sum(attack_impl_train_count) * 100 if sum(attack_impl_train_count) > 0 else '-', 
                    "#Test": test_count,
                    '%Test': test_count / sum(attack_impl_test_count) * 100,
                }
            overview[(attack_class, 'ALL')] = {
                "#Original": (attack_class == y_multi).sum(), 
                "#Sampled": sum(attack_impl_train_count) + sum(attack_impl_test_count), 
                "#Train": 0, 
                "#Validation": sum(attack_impl_train_count) if sum(attack_impl_train_count) > 0 else '-', 
                '%Validation': 100 if sum(attack_impl_train_count) > 0 else '-', 
                "#Test": sum(attack_impl_test_count),
                '%Test': 100,
            }
        print(pd.DataFrame.from_dict(overview, orient="index").rename_axis(["Class", "Impl"]))
    
    # Prepare final datasets
#     x_binary_val = np.concatenate((x_benign_val, x_malicious_train))
#     y_binary_val = np.concatenate((y_benign_val, np.full(y_malicious_train.shape[0], -1)))

#     x_binary_test = np.concatenate((x_benign_test, x_malicious_test))
#     y_binary_test = np.concatenate((y_benign_test, np.full(y_malicious_test.shape[0], -1)))
    
    return (x_benign_train, y_benign_train, x_benign_val, y_benign_val, x_benign_test, y_benign_test, x_malicious_train, y_malicious_train, x_malicious_test, y_malicious_test, attack_type_train, attack_type_test, attack_type)

def sub_sample_train_test(df, attack_type_label, sample_size, train_size=0.7, random_seed=42):
    # Returns indexes of train and test split
    # Classes with not enough samples will all be in the test split
    random_state = np.random.RandomState(random_seed)
    train_idx = np.empty((0,), dtype=int)
    test_idx = np.empty((0,), dtype=int)

    for attack_type in np.unique(df.Label):
        attack_type_count = np.count_nonzero(df.Label == attack_type)
        if attack_type_count < sample_size:
            # Use attack class for testing only, not enough samples for training
            test_idx = np.concatenate((test_idx, np.flatnonzero(df.Label == attack_type)))
        else:
            # Splits attack class over train and test set in stratified manner
            attack_train_idx, attack_test_idx = train_test_split(range(attack_type_count), test_size=round(sample_size*(1-train_size)), train_size=round(sample_size*train_size), random_state=random_seed, stratify=attack_type_label[df.Label == attack_type])
            attack_original_idx = np.flatnonzero(df.Label == attack_type)
            train_idx = np.concatenate((train_idx, attack_original_idx[attack_train_idx]))
            test_idx = np.concatenate((test_idx, attack_original_idx[attack_test_idx]))

    random_state.shuffle(train_idx)
    random_state.shuffle(test_idx)
    return (train_idx, test_idx)

def anomaly_scores(original, transformed):
    sse = np.sum((original - transformed)**2, axis=1)
    return sse

def evaluate_results(y_true, score):
    precision, recall, threshold = precision_recall_curve(y_true, score, pos_label=-1)
    au_precision_recall = auc(recall, precision)
    results = pd.DataFrame({'precision': precision, 'recall': recall})
    results["f1"] = 2*precision*recall/(precision+recall)
    results["f2"] = 5*precision*recall/(4*precision+recall)
    max_index_f1 = results["f1"].idxmax()
    max_index_f2 = results["f2"].idxmax()
    best = pd.concat([results.loc[max_index_f1], results.loc[max_index_f2]], keys= ["f1", "f2"])
    best["f1threshold"] = threshold[max_index_f1]
    best["f2threshold"] = threshold[max_index_f2]
    best["au_precision_recall"] = au_precision_recall
    fpr, tpr, thresholds = roc_curve(y_true, score, pos_label=-1)
    best["auroc"] = auc(fpr, tpr)
    return best

def evaluate_proba(y_true, score):
    precision, recall, threshold = precision_recall_curve(y_true, score, pos_label=-1)
    results = pd.DataFrame({'precision': precision, 'recall': recall, 'threshold': np.append(threshold, np.inf)})
    best_index_fscore = {}
    f_scores = []
    for i in range(1, 10):
        results[f"F{i}"] = (1+i**2)*precision*recall/(i**2*precision+recall)
        best_index = results[f"F{i}"].idxmax()
        f_scores.append({
            "metric": f"F{i}", 
            "value": str(round(results[f'F{i}'][best_index], 4)), 
            "threshold": threshold[best_index],
            "precision": str(round(results["precision"][best_index], 4)),
            "recall": str(round(results["recall"][best_index], 4)),
            "FPR": (score[(y_true == 1)] >= threshold[best_index]).sum() / (y_true == 1).sum()
        })
    return results, pd.DataFrame(f_scores)

def plot_fscores(scores, summary, figsize=(10,6), min_recall=0.25, show_thresholds=False):
    n_points = sum(scores['recall'] >= min_recall)
    fig, ax = plt.subplots(figsize=figsize)
    ax.plot(scores.loc[:n_points, 'threshold'], scores.loc[:n_points, 'recall'], label="recall", color="black")
    ax.plot(scores.loc[:n_points, 'threshold'], scores.loc[:n_points, 'precision'], label="precision", color="silver")
    colors = ["tab:blue", "tab:orange", "tab:green", "tab:red", "tab:purple", "tab:brown", "tab:pink", "tab:gray", "tab:olive", "tab:cyan"]
    n_curves = 0
    thresholds = []
    for f_col in scores.filter(regex="^F.+"):
        ax.plot(scores.loc[:n_points, 'threshold'], scores.loc[:n_points, f_col], label=f_col, color=colors[n_curves%len(colors)])
        ax.plot(float(summary.loc[summary.metric == f_col, "threshold"]), float(summary.loc[summary.metric == f_col, "value"]), marker="o", color=colors[n_curves%len(colors)])
        thresholds.append(float(summary.loc[summary.metric == f_col, "threshold"]))
        n_curves += 1
    if show_thresholds:
        for t in thresholds:
            ax.axvline(t, 0, 1, color="black", linestyle="--")
    ax.set_xlabel("threshold")
    ax.set_ylabel("value")
    plt.legend()
    return fig

def plot_confusion_matrix(y_true, y_pred, figsize=(7,7), cmap="Blues", values=[-1, 1], labels=["fraud", "benign"], title="", ax=None):
    cm = confusion_matrix(y_true, y_pred, labels=values)
    cm_sum = np.sum(cm, axis=1, keepdims=True)
    cm_perc = cm / cm_sum.astype(float)
    annot = np.empty_like(cm).astype(str)
    nrows, ncols = cm.shape
    for i in range(nrows):
        for j in range(ncols):
            c = cm[i, j]
            p = cm_perc[i, j]
            annot[i, j] = '%.1f%%\n%d' % (p * 100, c)
    cm_perc = pd.DataFrame(cm_perc, index=labels, columns=labels)
    cm_perc.index.name = 'Actual'
    cm_perc.columns.name = 'Predicted'
    if ax == None:
        fig, ax = plt.subplots(figsize=figsize)
    sns.heatmap(cm_perc, cmap=cmap, annot=annot, fmt='', ax=ax, vmin=0, vmax=1)
    if title != "":
        ax.set_title(title)

def optimal_fscore_multi(y_true, score, classes, steps=100, start_step=0.0, stop_step=1.0):
    thresholds = np.arange(0.0, 1.0, 1/steps)
    fmacro = np.zeros(shape=(len(thresholds)))
    fweight = np.zeros(shape=(len(thresholds)))
    metrics = {
        "f1_macro": 0,
        "f1_macro_threshold": None,
        "f1_weighted": 0,
        "f1_weighted_threshold": None,
    }
    for index, threshold in enumerate(thresholds):
        # Corrected probabilities
        y_pred = np.where(np.max(score, axis=1) > threshold, classes[np.argmax(score, axis=1)], 'Unknown')
        # Calculate the f-score
        fmacro[index] = f1_score(y_true, y_pred, average='macro')
        if fmacro[index] > metrics["f1_macro"]:
            metrics["f1_macro"] = fmacro[index]
            metrics["f1_macro_threshold"] = threshold
            
        fweight[index] = f1_score(y_true, y_pred, average='weighted')
        if fweight[index] > metrics["f1_weighted"]:
            metrics["f1_weighted"] = fweight[index]
            metrics["f1_weighted_threshold"] = threshold
    return fmacro, fweight, thresholds, metrics

def plot_f_multi(fmacro, fweight, thresholds, metrics, figsize=(8,6)):
    fig, ax = plt.subplots(figsize=figsize)
    ax.plot(thresholds, fmacro, label=f"F1 Macro ({round(metrics['f1_macro'], 3)})", color="tab:blue")
    ax.plot(thresholds, fweight, label=f"F1 Weight ({round(metrics['f1_weighted'],3)})", color="tab:orange")
    ax.plot(metrics["f1_macro_threshold"], metrics["f1_macro"], marker="o")
    ax.plot(metrics["f1_weighted_threshold"], metrics["f1_weighted"], marker="o")
    ax.set_xlabel("threshold")
    ax.set_ylabel("value")
    plt.legend()
    return fig
