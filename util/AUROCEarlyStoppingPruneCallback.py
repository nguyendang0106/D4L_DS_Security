# from keras.callbacks import Callback
from tensorflow.keras.callbacks import Callback
from sklearn.metrics import auc, roc_curve
import numpy as np
import warnings
import optuna

class AUROCEarlyStoppingPruneCallback(Callback):
    """Stop training when a monitored quantity has stopped improving.
    # Arguments
        x_val:
            Input vector of validation data.
        y_val:
            Labels for input vector of validation data.
        trial:
            A :class:`~optuna.trial.Trial` corresponding to the current evaluation of the
            objective function.
        min_delta: minimum change in the monitored quantity
            to qualify as an improvement, i.e. an absolute
            change of less than min_delta, will count as no
            improvement.
        patience: number of epochs that produced the monitored
            quantity with no improvement after which training will
            be stopped.
            Validation quantities may not be produced for every
            epoch, if the validation frequency
            (`model.fit(validation_freq=5)`) is greater than one.
        verbose: verbosity mode.
        mode: one of {auto, min, max}. In `min` mode,
            training will stop when the quantity
            monitored has stopped decreasing; in `max`
            mode it will stop when the quantity
            monitored has stopped increasing; in `auto`
            mode, the direction is automatically inferred
            from the name of the monitored quantity.
        baseline: Baseline value for the monitored quantity to reach.
            Training will stop if the model doesn't show improvement
            over the baseline.
        restore_best_weights: whether to restore model weights from
            the epoch with the best value of the monitored quantity.
            If False, the model weights obtained at the last step of
            training are used.
    """

    def __init__(self,
                 x_val, 
                 y_val, 
                 trail,
                 min_delta=0,
                 patience=0,
                 verbose=0,
                 mode='auto',
                 baseline=None,
                 restore_best_weights=False):
        super(AUROCEarlyStoppingPruneCallback, self).__init__()

        self.x_val = x_val
        self.y_val = y_val
        self.trail = trail
        self.baseline = baseline
        self.patience = patience
        self.verbose = verbose
        self.min_delta = min_delta
        self.wait = 0
        self.stopped_epoch = 0
        self.restore_best_weights = restore_best_weights
        self.best_weights = None

        if mode not in ['auto', 'min', 'max']:
            warnings.warn('EarlyStopping mode %s is unknown, '
                          'fallback to auto mode.' % mode,
                          RuntimeWarning)
            mode = 'auto'

        if mode == 'min':
            self.monitor_op = np.less
        else:
            self.monitor_op = np.greater

        if self.monitor_op == np.greater:
            self.min_delta *= 1
        else:
            self.min_delta *= -1

    def on_train_begin(self, logs=None):
        # Allow instances to be re-used
        self.wait = 0
        self.stopped_epoch = 0
        if self.baseline is not None:
            self.best = self.baseline
        else:
            self.best = np.Inf if self.monitor_op == np.less else -np.Inf

    def on_epoch_end(self, epoch, logs=None):
        current = self.get_AUROC()
        if current is None:
            return
        
        if self.verbose > 0:
            print(f'Epoch #{epoch}\tValidation AUROC: {current}\tBest AUROC: {self.best}')
        
        # Added support for pruning with optuna
        self.trail.report(float(current), step=epoch)
        if self.trail.should_prune():
            message = "Trial was pruned at epoch {}.".format(epoch)
            if self.verbose > 0:
                print(message)
            raise optuna.exceptions.TrialPruned(message)

        if self.monitor_op(current - self.min_delta, self.best):
            self.best = current
            self.wait = 0
            if self.restore_best_weights:
                self.best_weights = self.model.get_weights()
        else:
            self.wait += 1
            if self.wait >= self.patience:
                self.stopped_epoch = epoch
                self.model.stop_training = True
                if self.restore_best_weights:
                    if self.verbose > 0:
                        print('Restoring model weights from the end of '
                              'the best epoch')
                    self.model.set_weights(self.best_weights)

    def on_train_end(self, logs=None):
        if self.stopped_epoch > 0 and self.verbose > 0:
            print('Epoch %05d: early stopping' % (self.stopped_epoch + 1))
    
    # Evaluation on custom metric
    def get_AUROC(self):
        x_pred = self.model.predict(self.x_val)
        sse = np.sum((self.x_val - x_pred)**2, axis=1)
        fpr, tpr, thresholds = roc_curve(self.y_val, sse, pos_label=-1)
        return auc(fpr, tpr)
